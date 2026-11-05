/* izenpe_pkcs11.c — thin PKCS#11 module for Izenpe Tarjeta Virtual (Linux).
 *
 * Loaded by NSS/Firefox/Chrome/AutoFirma. All real work (object enumeration, remote
 * signing) is delegated to the izenpe-tv-agent over a local AF_UNIX socket using a
 * compact binary protocol (see src/izenpe_tv/agent.py: BINARY_MAGIC / OP_*).
 *
 * Read-only token: exposes, per signing identity, one CKO_CERTIFICATE + one
 * CKO_PRIVATE_KEY (+ CKO_PUBLIC_KEY). Signing mechanisms: CKM_RSA_PKCS,
 * CKM_RSA_PKCS_PSS and the combined CKM_{SHA1,SHA256,SHA384,SHA512}_RSA_PKCS[_PSS].
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(rt, name) rt name
#define CK_DECLARE_FUNCTION_POINTER(rt, name) rt (CK_PTR name)
#define CK_CALLBACK_FUNCTION(rt, name) rt (CK_PTR name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

/* ------------------------------------------------------------------ config */

#define OP_PING 1
#define OP_LIST 2
#define OP_SIGN 3
#define MAX_OBJECTS 64
#define SLOT_ID 1

typedef struct {
    unsigned char id[64]; uint32_t id_len;      /* CKA_ID (sha1 of cert DER) */
    char label[256]; uint32_t label_len;
    unsigned char *cert; uint32_t cert_len;      /* X.509 DER */
    unsigned char *modulus; uint32_t modulus_len;
    unsigned char *exponent; uint32_t exponent_len;
    unsigned char *subject; uint32_t subject_len;
    unsigned char *issuer; uint32_t issuer_len;
    unsigned char *serial; uint32_t serial_len;
    uint32_t modulus_bits;
} identity_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
static identity_t g_ids[MAX_OBJECTS];
static uint32_t g_nids = 0;
static int g_objects_loaded = 0;

/* one session (single-session token is enough for NSS client auth / signing) */
static int g_session_open = 0;
static CK_SESSION_HANDLE g_session = 1;

/* find-objects state */
static int g_find_active = 0;
static CK_OBJECT_HANDLE g_find_results[MAX_OBJECTS * 3];
static uint32_t g_find_count = 0, g_find_pos = 0;

/* sign state */
static int g_sign_active = 0;
static CK_MECHANISM_TYPE g_sign_mech = 0;
static uint32_t g_sign_key_idx = 0;        /* identity index */
static unsigned char *g_sign_buf = NULL;   /* accumulated data for multi-part */
static uint32_t g_sign_buf_len = 0, g_sign_buf_cap = 0;
static CK_MECHANISM_TYPE g_pss_hash = 0;   /* hashAlg from CK_RSA_PKCS_PSS_PARAMS */

/* Object handle encoding:
 *   class in top bits: 1=cert, 2=privkey, 3=pubkey ; index in low bits */
#define H_CLASS(h) ((h) >> 24)
#define H_INDEX(h) ((h) & 0x00FFFFFF)
#define H_MAKE(cls, idx) (((CK_OBJECT_HANDLE)(cls) << 24) | ((idx) & 0x00FFFFFF))
#define CLS_CERT 1
#define CLS_PRIV 2
#define CLS_PUB 3

/* ------------------------------------------------------------- agent socket */

static int agent_connect(void) {
    const char *path = getenv("IZENPE_TV_SOCK");
    char buf[256];
    if (!path || !*path) {
        const char *run = getenv("XDG_RUNTIME_DIR");
        if (run && *run) snprintf(buf, sizeof buf, "%s/izenpe-tv.sock", run);
        else snprintf(buf, sizeof buf, "/run/user/%d/izenpe-tv.sock", (int)getuid());
        path = buf;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr; memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    const char magic[4] = {'I','Z','T','V'};
    if (write(fd, magic, 4) != 4) { close(fd); return -1; }
    return fd;
}

static int read_all(int fd, void *buf, size_t n) {
    unsigned char *p = buf; size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf; size_t put = 0;
    while (put < n) {
        ssize_t w = write(fd, p + put, n - put);
        if (w <= 0) return -1;
        put += (size_t)w;
    }
    return 0;
}

static uint32_t be32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static void put_be32(unsigned char *b, uint32_t v) {
    b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v;
}

/* read a u32-length-prefixed field into a malloc'd buffer */
static int read_field(int fd, unsigned char **out, uint32_t *out_len) {
    unsigned char hdr[4];
    if (read_all(fd, hdr, 4) < 0) return -1;
    uint32_t n = be32(hdr);
    unsigned char *p = malloc(n ? n : 1);
    if (!p) return -1;
    if (n && read_all(fd, p, n) < 0) { free(p); return -1; }
    *out = p; *out_len = n;
    return 0;
}

static void free_identities(void) {
    for (uint32_t i = 0; i < g_nids; i++) {
        free(g_ids[i].cert); free(g_ids[i].modulus); free(g_ids[i].exponent);
        free(g_ids[i].subject); free(g_ids[i].issuer); free(g_ids[i].serial);
    }
    memset(g_ids, 0, sizeof g_ids);
    g_nids = 0;
}

/* Fetch identities from the agent (OP_LIST). Returns 0 on success. */
static int load_identities(void) {
    int fd = agent_connect();
    if (fd < 0) return -1;
    unsigned char op = OP_LIST;
    if (write_all(fd, &op, 1) < 0) { close(fd); return -1; }
    unsigned char status;
    if (read_all(fd, &status, 1) < 0 || status != 0) { close(fd); return -1; }
    unsigned char cntb[4];
    if (read_all(fd, cntb, 4) < 0) { close(fd); return -1; }
    uint32_t cnt = be32(cntb);
    if (cnt > MAX_OBJECTS) cnt = MAX_OBJECTS;
    free_identities();
    for (uint32_t i = 0; i < cnt; i++) {
        identity_t *d = &g_ids[i];
        unsigned char *f; uint32_t fl;
        if (read_field(fd, &f, &fl) < 0) goto fail;
        d->id_len = fl > sizeof d->id ? sizeof d->id : fl; memcpy(d->id, f, d->id_len); free(f);
        if (read_field(fd, &f, &fl) < 0) goto fail;
        d->label_len = fl > sizeof d->label - 1 ? sizeof d->label - 1 : fl;
        memcpy(d->label, f, d->label_len); d->label[d->label_len] = 0; free(f);
        if (read_field(fd, &d->cert, &d->cert_len) < 0) goto fail;
        if (read_field(fd, &d->modulus, &d->modulus_len) < 0) goto fail;
        if (read_field(fd, &d->exponent, &d->exponent_len) < 0) goto fail;
        if (read_field(fd, &d->subject, &d->subject_len) < 0) goto fail;
        if (read_field(fd, &d->issuer, &d->issuer_len) < 0) goto fail;
        if (read_field(fd, &d->serial, &d->serial_len) < 0) goto fail;
        unsigned char bitsb[4];
        if (read_all(fd, bitsb, 4) < 0) goto fail;
        d->modulus_bits = be32(bitsb);
        g_nids = i + 1;
    }
    close(fd);
    g_objects_loaded = 1;
    return 0;
fail:
    close(fd);
    return -1;
}

/* mechanism type -> agent mechanism string */
static const char *mech_name(CK_MECHANISM_TYPE m) {
    switch (m) {
    case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
    case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
    case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";
    case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
    case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
    case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
    case CKM_SHA1_RSA_PKCS_PSS: return "CKM_SHA1_RSA_PKCS_PSS";
    case CKM_SHA256_RSA_PKCS_PSS: return "CKM_SHA256_RSA_PKCS_PSS";
    case CKM_SHA384_RSA_PKCS_PSS: return "CKM_SHA384_RSA_PKCS_PSS";
    case CKM_SHA512_RSA_PKCS_PSS: return "CKM_SHA512_RSA_PKCS_PSS";
    default: return NULL;
    }
}

static const char *pss_hash_name(CK_MECHANISM_TYPE h) {
    switch (h) {
    case CKM_SHA_1: return "sha1";
    case CKM_SHA256: return "sha256";
    case CKM_SHA384: return "sha384";
    case CKM_SHA512: return "sha512";
    default: return "sha256";
    }
}

/* Ask the agent to sign. Returns malloc'd signature or NULL. */
static unsigned char *agent_sign(uint32_t idx, CK_MECHANISM_TYPE mech,
                                 const char *hash_hint,
                                 const unsigned char *data, uint32_t data_len,
                                 uint32_t *sig_len) {
    const char *mname = mech_name(mech);
    if (!mname) return NULL;
    int fd = agent_connect();
    if (fd < 0) return NULL;

    /* id as lowercase hex */
    char hexid[129]; identity_t *d = &g_ids[idx];
    for (uint32_t i = 0; i < d->id_len; i++) sprintf(hexid + 2 * i, "%02x", d->id[i]);
    uint32_t hexlen = d->id_len * 2;
    uint32_t mlen = (uint32_t)strlen(mname);
    uint32_t hlen = hash_hint ? (uint32_t)strlen(hash_hint) : 0;

    size_t total = 1 + 4 + hexlen + 4 + mlen + 4 + hlen + 4 + data_len;
    unsigned char *req = malloc(total);
    if (!req) { close(fd); return NULL; }
    size_t o = 0;
    req[o++] = OP_SIGN;
    put_be32(req + o, hexlen); o += 4; memcpy(req + o, hexid, hexlen); o += hexlen;
    put_be32(req + o, mlen); o += 4; memcpy(req + o, mname, mlen); o += mlen;
    put_be32(req + o, hlen); o += 4; if (hlen) { memcpy(req + o, hash_hint, hlen); o += hlen; }
    put_be32(req + o, data_len); o += 4; memcpy(req + o, data, data_len); o += data_len;

    int wr = write_all(fd, req, total);
    free(req);
    if (wr < 0) { close(fd); return NULL; }

    unsigned char status;
    if (read_all(fd, &status, 1) < 0 || status != 0) { close(fd); return NULL; }
    unsigned char *sig; uint32_t sl;
    if (read_field(fd, &sig, &sl) < 0) { close(fd); return NULL; }
    close(fd);
    *sig_len = sl;
    return sig;
}

/* ------------------------------------------------------------- CK helpers */

static CK_RV set_attr(CK_ATTRIBUTE *a, const void *val, CK_ULONG len) {
    if (a->pValue == NULL_PTR) { a->ulValueLen = len; return CKR_OK; }
    if (a->ulValueLen < len) { a->ulValueLen = (CK_ULONG)-1; return CKR_BUFFER_TOO_SMALL; }
    memcpy(a->pValue, val, len); a->ulValueLen = len; return CKR_OK;
}

/* ------------------------------------------------------------- CK functions */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    pthread_mutex_lock(&g_lock);
    if (g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_ALREADY_INITIALIZED; }
    g_initialized = 1; g_objects_loaded = 0; g_nids = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved;
    pthread_mutex_lock(&g_lock);
    free_identities();
    free(g_sign_buf); g_sign_buf = NULL; g_sign_buf_len = g_sign_buf_cap = 0;
    g_initialized = 0; g_objects_loaded = 0; g_session_open = 0; g_find_active = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR p) {
    if (!p) return CKR_ARGUMENTS_BAD;
    memset(p, 0, sizeof *p);
    p->cryptokiVersion.major = 2; p->cryptokiVersion.minor = 40;
    memset(p->manufacturerID, ' ', 32); memcpy(p->manufacturerID, "Izenpe TV Linux", 15);
    memset(p->libraryDescription, ' ', 32); memcpy(p->libraryDescription, "Izenpe Tarjeta Virtual", 22);
    p->libraryVersion.major = 0; p->libraryVersion.minor = 1;
    return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    (void)tokenPresent;
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (pSlotList == NULL_PTR) { *pulCount = 1; return CKR_OK; }
    if (*pulCount < 1) { *pulCount = 1; return CKR_BUFFER_TOO_SMALL; }
    pSlotList[0] = SLOT_ID; *pulCount = 1;
    return CKR_OK;
}

static void pad_field(CK_UTF8CHAR *dst, size_t n, const char *src) {
    memset(dst, ' ', n);
    size_t l = strlen(src); if (l > n) l = n; memcpy(dst, src, l);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR p) {
    if (slotID != SLOT_ID || !p) return CKR_SLOT_ID_INVALID;
    memset(p, 0, sizeof *p);
    pad_field(p->slotDescription, 64, "Izenpe Tarjeta Virtual (remote)");
    pad_field(p->manufacturerID, 32, "Izenpe");
    p->flags = CKF_TOKEN_PRESENT;
    p->hardwareVersion.major = 0; p->hardwareVersion.minor = 1;
    p->firmwareVersion.major = 0; p->firmwareVersion.minor = 1;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR p) {
    if (slotID != SLOT_ID || !p) return CKR_SLOT_ID_INVALID;
    memset(p, 0, sizeof *p);
    pad_field(p->label, 32, "Izenpe TV");
    pad_field(p->manufacturerID, 32, "Izenpe");
    pad_field(p->model, 16, "cloud");
    pad_field(p->serialNumber, 16, "0001");
    p->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
    p->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    p->ulSessionCount = g_session_open ? 1 : 0;
    p->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    p->ulMaxPinLen = 0; p->ulMinPinLen = 0;
    p->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    p->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    p->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    p->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    p->hardwareVersion.major = 0; p->hardwareVersion.minor = 1;
    p->firmwareVersion.major = 0; p->firmwareVersion.minor = 1;
    return CKR_OK;
}

static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
};

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pList, CK_ULONG_PTR pulCount) {
    if (slotID != SLOT_ID || !pulCount) return CKR_SLOT_ID_INVALID;
    CK_ULONG n = sizeof g_mechs / sizeof g_mechs[0];
    if (pList == NULL_PTR) { *pulCount = n; return CKR_OK; }
    if (*pulCount < n) { *pulCount = n; return CKR_BUFFER_TOO_SMALL; }
    memcpy(pList, g_mechs, sizeof g_mechs); *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR p) {
    if (slotID != SLOT_ID || !p) return CKR_SLOT_ID_INVALID;
    if (!mech_name(type)) return CKR_MECHANISM_INVALID;
    memset(p, 0, sizeof *p);
    p->ulMinKeySize = 1024; p->ulMaxKeySize = 4096;
    p->flags = CKF_SIGN;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR app,
                    CK_NOTIFY notify, CK_SESSION_HANDLE_PTR ph) {
    (void)flags; (void)app; (void)notify;
    if (slotID != SLOT_ID || !ph) return CKR_SLOT_ID_INVALID;
    pthread_mutex_lock(&g_lock);
    g_session_open = 1;
    *ph = g_session;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE h) {
    (void)h;
    pthread_mutex_lock(&g_lock);
    g_session_open = 0; g_find_active = 0; g_sign_active = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) { (void)slotID; return C_CloseSession(0); }

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR p) {
    (void)h;
    if (!p) return CKR_ARGUMENTS_BAD;
    p->slotID = SLOT_ID;
    p->state = CKS_RO_USER_FUNCTIONS;
    p->flags = CKF_SERIAL_SESSION;
    p->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE h, CK_USER_TYPE t, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
    (void)h; (void)t; (void)pin; (void)len;
    return CKR_OK;  /* auth happens out-of-band (agent holds the OAuth session) */
}
CK_RV C_Logout(CK_SESSION_HANDLE h) { (void)h; return CKR_OK; }

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count) {
    (void)h;
    pthread_mutex_lock(&g_lock);
    if (!g_objects_loaded) load_identities();  /* best-effort; empty list if agent down */

    /* parse template filters we care about: CKA_CLASS and CKA_ID */
    int want_class = -1; CK_OBJECT_CLASS cls = 0;
    const unsigned char *want_id = NULL; CK_ULONG want_id_len = 0;
    for (CK_ULONG i = 0; i < count; i++) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue) {
            cls = *(CK_OBJECT_CLASS *)pTemplate[i].pValue; want_class = 1;
        } else if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue) {
            want_id = pTemplate[i].pValue; want_id_len = pTemplate[i].ulValueLen;
        }
    }

    g_find_count = 0; g_find_pos = 0;
    for (uint32_t i = 0; i < g_nids; i++) {
        if (want_id) {
            if (want_id_len != g_ids[i].id_len || memcmp(want_id, g_ids[i].id, want_id_len) != 0)
                continue;
        }
        int add_cert = 1, add_priv = 1, add_pub = 1;
        if (want_class == 1) {
            add_cert = (cls == CKO_CERTIFICATE);
            add_priv = (cls == CKO_PRIVATE_KEY);
            add_pub = (cls == CKO_PUBLIC_KEY);
        }
        if (add_cert) g_find_results[g_find_count++] = H_MAKE(CLS_CERT, i);
        if (add_priv) g_find_results[g_find_count++] = H_MAKE(CLS_PRIV, i);
        if (add_pub) g_find_results[g_find_count++] = H_MAKE(CLS_PUB, i);
    }
    g_find_active = 1;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR ph, CK_ULONG maxc, CK_ULONG_PTR pn) {
    (void)h;
    if (!g_find_active) return CKR_OPERATION_NOT_INITIALIZED;
    CK_ULONG n = 0;
    while (g_find_pos < g_find_count && n < maxc) ph[n++] = g_find_results[g_find_pos++];
    *pn = n;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE h) { (void)h; g_find_active = 0; return CKR_OK; }

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE obj,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count) {
    (void)h;
    uint32_t idx = H_INDEX(obj); unsigned cls = H_CLASS(obj);
    if (idx >= g_nids) return CKR_OBJECT_HANDLE_INVALID;
    identity_t *d = &g_ids[idx];
    CK_RV rv = CKR_OK;
    CK_BBOOL ck_true = CK_TRUE, ck_false = CK_FALSE;
    CK_OBJECT_CLASS oc = cls == CLS_CERT ? CKO_CERTIFICATE :
                         cls == CLS_PRIV ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_KEY_TYPE kt = CKK_RSA;
    CK_CERTIFICATE_TYPE ctype = CKC_X_509;

    for (CK_ULONG i = 0; i < count; i++) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        CK_RV r = CKR_OK;
        switch (a->type) {
        case CKA_CLASS: r = set_attr(a, &oc, sizeof oc); break;
        case CKA_TOKEN: r = set_attr(a, &ck_true, sizeof ck_true); break;
        case CKA_PRIVATE:
            r = set_attr(a, cls == CLS_PRIV ? &ck_true : &ck_false, sizeof ck_true); break;
        case CKA_MODIFIABLE: r = set_attr(a, &ck_false, sizeof ck_false); break;
        case CKA_LABEL: r = set_attr(a, d->label, d->label_len); break;
        case CKA_ID: r = set_attr(a, d->id, d->id_len); break;
        default:
            if (cls == CLS_CERT) {
                switch (a->type) {
                case CKA_CERTIFICATE_TYPE: r = set_attr(a, &ctype, sizeof ctype); break;
                case CKA_VALUE: r = set_attr(a, d->cert, d->cert_len); break;
                case CKA_SUBJECT: r = set_attr(a, d->subject, d->subject_len); break;
                case CKA_ISSUER: r = set_attr(a, d->issuer, d->issuer_len); break;
                case CKA_SERIAL_NUMBER: r = set_attr(a, d->serial, d->serial_len); break;
                case CKA_TRUSTED: r = set_attr(a, &ck_false, sizeof ck_false); break;
                default: a->ulValueLen = (CK_ULONG)-1; r = CKR_ATTRIBUTE_TYPE_INVALID;
                }
            } else {  /* private or public key */
                switch (a->type) {
                case CKA_KEY_TYPE: r = set_attr(a, &kt, sizeof kt); break;
                case CKA_SIGN:
                    r = set_attr(a, cls == CLS_PRIV ? &ck_true : &ck_false, sizeof ck_true); break;
                case CKA_VERIFY:
                    r = set_attr(a, cls == CLS_PUB ? &ck_true : &ck_false, sizeof ck_true); break;
                case CKA_DECRYPT: case CKA_UNWRAP: case CKA_DERIVE:
                    r = set_attr(a, &ck_false, sizeof ck_false); break;
                case CKA_SENSITIVE: case CKA_ALWAYS_SENSITIVE:
                    r = set_attr(a, cls == CLS_PRIV ? &ck_true : &ck_false, sizeof ck_true); break;
                case CKA_EXTRACTABLE: r = set_attr(a, &ck_false, sizeof ck_false); break;
                case CKA_NEVER_EXTRACTABLE: r = set_attr(a, &ck_true, sizeof ck_true); break;
                case CKA_MODULUS: r = set_attr(a, d->modulus, d->modulus_len); break;
                case CKA_PUBLIC_EXPONENT: r = set_attr(a, d->exponent, d->exponent_len); break;
                case CKA_MODULUS_BITS: {
                    CK_ULONG mb = d->modulus_bits; r = set_attr(a, &mb, sizeof mb); break;
                }
                case CKA_SUBJECT: r = set_attr(a, d->subject, d->subject_len); break;
                case CKA_ALWAYS_AUTHENTICATE: r = set_attr(a, &ck_false, sizeof ck_false); break;
                default: a->ulValueLen = (CK_ULONG)-1; r = CKR_ATTRIBUTE_TYPE_INVALID;
                }
            }
        }
        if (r != CKR_OK) rv = r;
    }
    return rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR pMech, CK_OBJECT_HANDLE key) {
    (void)h;
    if (!pMech) return CKR_ARGUMENTS_BAD;
    if (!mech_name(pMech->mechanism)) return CKR_MECHANISM_INVALID;
    uint32_t idx = H_INDEX(key);
    if (H_CLASS(key) != CLS_PRIV || idx >= g_nids) return CKR_KEY_HANDLE_INVALID;
    pthread_mutex_lock(&g_lock);
    g_sign_active = 1; g_sign_mech = pMech->mechanism; g_sign_key_idx = idx;
    g_sign_buf_len = 0; g_pss_hash = 0;
    if ((pMech->mechanism == CKM_RSA_PKCS_PSS || pMech->mechanism == CKM_SHA1_RSA_PKCS_PSS ||
         pMech->mechanism == CKM_SHA256_RSA_PKCS_PSS || pMech->mechanism == CKM_SHA384_RSA_PKCS_PSS ||
         pMech->mechanism == CKM_SHA512_RSA_PKCS_PSS) &&
        pMech->pParameter && pMech->ulParameterLen >= sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        CK_RSA_PKCS_PSS_PARAMS *pp = (CK_RSA_PKCS_PSS_PARAMS *)pMech->pParameter;
        g_pss_hash = pp->hashAlg;
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

static int sign_buf_append(const unsigned char *p, CK_ULONG n) {
    if (g_sign_buf_len + n > g_sign_buf_cap) {
        uint32_t ncap = g_sign_buf_cap ? g_sign_buf_cap * 2 : 4096;
        while (ncap < g_sign_buf_len + n) ncap *= 2;
        unsigned char *nb = realloc(g_sign_buf, ncap);
        if (!nb) return -1;
        g_sign_buf = nb; g_sign_buf_cap = ncap;
    }
    memcpy(g_sign_buf + g_sign_buf_len, p, n); g_sign_buf_len += n;
    return 0;
}

static CK_RV do_sign(CK_BYTE_PTR pData, CK_ULONG dataLen,
                     CK_BYTE_PTR pSig, CK_ULONG_PTR pSigLen) {
    /* Size query / short buffer: answer from the RSA modulus length WITHOUT contacting
     * the HSM (each remote call is a real signature). */
    CK_ULONG need = (g_ids[g_sign_key_idx].modulus_bits + 7) / 8;
    if (need == 0) need = g_ids[g_sign_key_idx].modulus_len;
    if (pSig == NULL_PTR) { *pSigLen = need; return CKR_OK; }
    if (*pSigLen < need) { *pSigLen = need; return CKR_BUFFER_TOO_SMALL; }

    const char *hint = NULL;
    if (g_sign_mech == CKM_RSA_PKCS_PSS) hint = pss_hash_name(g_pss_hash);
    uint32_t sl = 0;
    unsigned char *sig = agent_sign(g_sign_key_idx, g_sign_mech, hint, pData, (uint32_t)dataLen, &sl);
    if (!sig) return CKR_FUNCTION_FAILED;
    if (pSig == NULL_PTR) { *pSigLen = sl; free(sig); return CKR_OK; }
    if (*pSigLen < sl) { *pSigLen = sl; free(sig); return CKR_BUFFER_TOO_SMALL; }
    memcpy(pSig, sig, sl); *pSigLen = sl; free(sig);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG dataLen,
             CK_BYTE_PTR pSig, CK_ULONG_PTR pSigLen) {
    (void)h;
    if (!g_sign_active) return CKR_OPERATION_NOT_INITIALIZED;
    CK_RV rv = do_sign(pData, dataLen, pSig, pSigLen);
    if (pSig != NULL_PTR && rv != CKR_BUFFER_TOO_SMALL) g_sign_active = 0;
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG partLen) {
    (void)h;
    if (!g_sign_active) return CKR_OPERATION_NOT_INITIALIZED;
    return sign_buf_append(pPart, partLen) == 0 ? CKR_OK : CKR_HOST_MEMORY;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pSig, CK_ULONG_PTR pSigLen) {
    (void)h;
    if (!g_sign_active) return CKR_OPERATION_NOT_INITIALIZED;
    CK_RV rv = do_sign(g_sign_buf, g_sign_buf_len, pSig, pSigLen);
    if (pSig != NULL_PTR && rv != CKR_BUFFER_TOO_SMALL) { g_sign_active = 0; g_sign_buf_len = 0; }
    return rv;
}

/* ---- stubs for the rest of the Cryptoki surface ---- */
CK_RV C_InitToken(CK_SLOT_ID a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d){(void)a;(void)b;(void)c;(void)d;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_InitPIN(CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SetPIN(CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d, CK_ULONG e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE d, CK_OBJECT_HANDLE e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_CreateObject(CK_SESSION_HANDLE a, CK_ATTRIBUTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE_PTR d){(void)a;(void)b;(void)c;(void)d;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_CopyObject(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_OBJECT_HANDLE_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DestroyObject(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b){(void)a;(void)b;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GetObjectSize(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ULONG_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE_PTR c, CK_ULONG d){(void)a;(void)b;(void)c;(void)d;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_EncryptInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_Encrypt(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_EncryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DecryptInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_Decrypt(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DecryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DigestInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b){(void)a;(void)b;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_Digest(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DigestUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DigestKey(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b){(void)a;(void)b;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DigestFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SignRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_VerifyInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_Verify(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_VerifyFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_VerifyRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GenerateKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_OBJECT_HANDLE_PTR e){(void)a;(void)b;(void)c;(void)d;(void)e;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_ATTRIBUTE_PTR e, CK_ULONG f, CK_OBJECT_HANDLE_PTR g, CK_OBJECT_HANDLE_PTR i){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)i;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_WrapKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_OBJECT_HANDLE d, CK_BYTE_PTR e, CK_ULONG_PTR f){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_UnwrapKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_BYTE_PTR d, CK_ULONG e, CK_ATTRIBUTE_PTR f, CK_ULONG g, CK_OBJECT_HANDLE_PTR i){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)i;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_DeriveKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_ATTRIBUTE_PTR d, CK_ULONG e, CK_OBJECT_HANDLE_PTR f){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_SeedRandom(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GenerateRandom(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE a){(void)a;return CKR_FUNCTION_NOT_PARALLEL;}
CK_RV C_CancelFunction(CK_SESSION_HANDLE a){(void)a;return CKR_FUNCTION_NOT_PARALLEL;}
CK_RV C_WaitForSlotEvent(CK_FLAGS a, CK_SLOT_ID_PTR b, CK_VOID_PTR c){(void)a;(void)b;(void)c;return CKR_FUNCTION_NOT_SUPPORTED;}

static CK_FUNCTION_LIST g_function_list = {
    .version = {2, 40},
    .C_Initialize = C_Initialize, .C_Finalize = C_Finalize, .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList, .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo, .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList, .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken, .C_InitPIN = C_InitPIN, .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession, .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions, .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState, .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login, .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject, .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject, .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue, .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit, .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit, .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate, .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit, .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate, .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit, .C_Digest = C_Digest, .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey, .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit, .C_Sign = C_Sign, .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal, .C_SignRecoverInit = C_SignRecoverInit, .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit, .C_Verify = C_Verify, .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal, .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate, .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate, .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey, .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey, .C_UnwrapKey = C_UnwrapKey, .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom, .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus, .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &g_function_list;
    return CKR_OK;
}
