#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h> // fingerprint.
#include <openssl/blowfish.h> // single packet blowfish encoding.
#include <openssl/rand.h>  // random generator.
#include <mt19937int.h>

static RSA* get_rsa(SV *sv)
{
  if (sv_derived_from(sv, "OpenSSL::RSAkey"))
    return (RSA*) SvIV(SvRV(sv));
  
  croak("Not a reference to a OpenSSL::RSAkey object");
  return (RSA*) 0;
}

static void run_sha1(char *digest, const char *msg, int msglen)
{
        SHA_CTX ctx;
        
       if(!digest || !msg || msglen < 0)
         croak("run_sha1: null pointer or illegal message len");
    	SHA1_Init(&ctx);
        SHA1_Update(&ctx, msg, msglen);
        SHA1_Final(digest, &ctx);	
}

static bool is_privkey(RSA *key)
{
   return (key->n && key->e && key->d && key->p && key->q
	  && key->dmp1 && key->dmq1 && key->iqmp && key->d) ? 1 : 0;
}


static SV* get_BN(BIGNUM *n)
{
  if (!n)
    croak("parse error :)");

  return newSVpv(BN_bn2dec(n), 0);
}


MODULE = OpenSSL::RSAkey		PACKAGE = OpenSSL::RSAkey		

void
new(xclass, bits = 128, e = 35)
	SV *xclass
  	IV bits
	IV e
  PREINIT:
  	RSA *key;
  PPCODE:
	EXTEND(sp, 1);
	PUSHs(sv_newmortal());
	key = RSA_generate_key(bits, e, NULL, NULL);
	sv_setref_pv(ST(0), "OpenSSL::RSAkey", (void *) key);

void
new_pubkey(xclass, n, e)
  	SV *xclass
        char *n
        char *e
  PREINIT:
	RSA *key;
  PPCODE:
  	EXTEND(sp, 1);
        PUSHs(sv_newmortal());
        key = RSA_new();
  	if (!key)
  		croak("can't allocate key");
        if(!(key->n = BN_new()) || !BN_dec2bn(&key->n, n)) {
  		RSA_free(key); croak("can't initialize n");
        }
	if(!(key->e = BN_new()) || !BN_dec2bn(&key->e, e)) {
  		RSA_free(key); croak("can't initialize e");
        }
        //key->p = 0, key->q = 0, key->dmp1 = 0, key->dmq1 = 0, key->iqmp = 0;
	sv_setref_pv(ST(0), "OpenSSL::RSAkey", (void *) key);
        
        
void
new_privkey(xclass, n, e, p, q, dmp1, dmq1, iqmp, d)
  	SV *xclass
        char *n
        char *e
        char *p
        char *q
        char *dmp1
        char *dmq1
        char *iqmp
        char *d
  PREINIT:
	RSA *key;
        int rc;
  PPCODE:
  	EXTEND(sp, 1);
        PUSHs(sv_newmortal());
        key = RSA_new();
  	if (!key)
  		croak("can't allocate key");
        if(!(key->n = BN_new()) || !BN_dec2bn(&key->n, n)) {
  		RSA_free(key); croak("can't initialize n");
        }
	if(!(key->e = BN_new()) || !BN_dec2bn(&key->e, e)) {
  		RSA_free(key); croak("can't initialize e");
        }
	if(!(key->p = BN_new()) || !BN_dec2bn(&key->p, p)) {
  		RSA_free(key); croak("can't initialize p");
        }
	if(!(key->q = BN_new()) || !BN_dec2bn(&key->q, q)) {
  		RSA_free(key); croak("can't initialize q");
        }
	if(!(key->dmp1 = BN_new()) || !BN_dec2bn(&key->dmp1, dmp1)) {
  		RSA_free(key); croak("can't initialize dmp1");
        }
	if(!(key->dmq1 = BN_new()) || !BN_dec2bn(&key->dmq1, dmq1)) {
  		RSA_free(key); croak("can't initialize dmq1");
        }
	if(!(key->iqmp = BN_new()) || !BN_dec2bn(&key->iqmp, iqmp)) {
  		RSA_free(key); croak("can't initialize iqmp");
        }
	if(!(key->d = BN_new()) || !BN_dec2bn(&key->d, d)) {
  		RSA_free(key); croak("can't initialize d");
        }
	if((rc = RSA_check_key(key)) != 1) {
  		RSA_free(key); croak("RSA_check_key failed (%d).", rc);
        }
	sv_setref_pv(ST(0), "OpenSSL::RSAkey", (void *) key);


void
DESTROY(key)
  RSA* key
  CODE:
	if (key)
	  RSA_free(key);

IV
keysize(key)
  	RSA *key;
  CODE:
  	if (!key || !key->n)
  		croak("invalid key");
	RETVAL = BN_num_bits(key->n);
OUTPUT:
	RETVAL

bool
check_key(key)
  	RSA *key;
PPCODE:
        if(!key)
  		XSRETURN_NO;
        if(RSA_check_key(key) == 1)
  		XSRETURN_YES;
        XSRETURN_NO;
        
  		



BIGNUM *
n(key)
  	RSA *key;
   ALIAS:
   e = 1
   d = 2
   p = 3
   q = 4
   dmp1 = 5
   dmq1 = 6
   iqmp = 7
   PREINIT:
   BIGNUM *bn = 0;
   CODE:
   	if(!key)
  		croak("invalid key");
  switch(ix) {
    case 0: bn = key->n; break;
    case 1: bn = key->e; break;
    case 2: bn = key->d; break;
    case 3: bn = key->p; break;
    case 4: bn = key->q; break;
    case 5: bn = key->dmp1; break;
    case 6: bn = key->dmq1; break;
    case 7: bn = key->iqmp; break;
    default:
      croak("huch");
  }
        if(!bn)
  		croak("bignum not defined (maybe pubkey ?)");
	RETVAL = bn;
OUTPUT:
	RETVAL


bool
is_privkey(key)
  	RSA *key;
   CODE:
   	RETVAL = is_privkey(key); 
   OUTPUT:
   	RETVAL

void
STORABLE_thaw(osv, cloning, sv)
  SV *osv
  bool cloning
  SV *sv
PREINIT:
  STRLEN len;
  char *p;
  unsigned int *i;
  RSA *key = NULL;
  PPCODE:
  	if(cloning)
  		return;
        i = (unsigned int *) SvPV(sv, len);
        if(i[2] == 0xffffffff) {
          // public key
	  key = RSA_new();
          p = (char *) &i[3];
          key->n =  BN_bin2bn(p, i[0], NULL);
          key->e =  BN_bin2bn(&p[i[0]], i[1], NULL);
        } else if (i[8] == 0xffffffff) {
          // private key
       	  key = RSA_new();
          p = (char *) &i[9];
	  key->n = BN_bin2bn(p, i[0], NULL);
          p += i[0];
          key->e = BN_bin2bn(p, i[1], NULL);
          p += i[1];
          key->d = BN_bin2bn(p, i[2], NULL);
          p += i[2];
          key->p = BN_bin2bn(p, i[3], NULL);
          p += i[3];
          key->q = BN_bin2bn(p, i[4], NULL);
          p += i[4];
          key->dmp1 = BN_bin2bn(p, i[5], NULL);
          p += i[5];
          key->dmq1 = BN_bin2bn(p, i[6], NULL);
          p += i[6];
          key->iqmp = BN_bin2bn(p, i[7], NULL);
        }
	if(!key)
          croak("Illegal Storable format.");
          sv_setiv(SvRV(osv), (IV) key);
          //sv_setref_pv(SvRV(osv), "OpenSSL::RSAkey", newRV_noinc((void *) key);
          //sv_setiv(osv, (IV) key);
	


void
STORABLE_freeze(key, cloning)
  	RSA *key
        bool cloning
PREINIT:
	SV *sv;
        STRLEN totlen;
PPCODE:
	if(cloning)
  		return;
        totlen = BN_num_bytes(key->n) + BN_num_bytes(key->e) + 3*sizeof(int);
        if(!is_privkey(key)) {
		int *y = malloc(totlen);
                int *x = y;
                char *p;
		*x++ = BN_num_bytes(key->n);
                *x++ = BN_num_bytes(key->e);
                *x++ = 0xffffffff;
                p = (char *) x;
                p += BN_bn2bin(key->n, p);
                p += BN_bn2bin(key->e, p);
                XPUSHs(sv_2mortal(newSVpvn((char *)y, p - (char *) y)));
                free(y);
        } else {
		int *y, *x;
                char *p;
                totlen += BN_num_bytes(key->d)
                  + BN_num_bytes(key->p)
                  + BN_num_bytes(key->q)
                  + BN_num_bytes(key->dmp1)
                  + BN_num_bytes(key->dmq1)
                  + BN_num_bytes(key->iqmp) + 6*sizeof(int);
		y = malloc(totlen);
                x = y;
		*x++ = BN_num_bytes(key->n);
                *x++ = BN_num_bytes(key->e);
		*x++ = BN_num_bytes(key->d);
                *x++ = BN_num_bytes(key->p);
		*x++ = BN_num_bytes(key->q);
                *x++ = BN_num_bytes(key->dmp1);
                *x++ = BN_num_bytes(key->dmq1);
                *x++ = BN_num_bytes(key->iqmp);
                *x++ = 0xffffffff;
                p = (char *) x;
                p += BN_bn2bin(key->n, p);
                p += BN_bn2bin(key->e, p);
                p += BN_bn2bin(key->d, p);
                p += BN_bn2bin(key->p, p);
                p += BN_bn2bin(key->q, p);
                p += BN_bn2bin(key->dmp1, p);
                p += BN_bn2bin(key->dmq1, p);
                p += BN_bn2bin(key->iqmp, p);
                XPUSHs(sv_2mortal(newSVpvn((char *)y, p - (char *) y)));
                free(y);
        }
        

void
public_encrypt(key, sv)
	RSA *key;
        SV *sv;
   ALIAS:
   encrypt = 0
   public_decrypt = 1
   verify = 1
   private_encrypt = 2
   sign = 2
   private_decrypt = 3
   decrypt = 3
   PREINIT:
   static int (*func[4])(int, unsigned char *, unsigned char *, RSA *, int) = { RSA_public_encrypt, RSA_public_decrypt, RSA_private_encrypt, RSA_private_decrypt };
   STRLEN len;
   int keylen;
   char *p;
   char out[1024]; // max. 8192 bit keys :)
   STRLEN rc;
   PPCODE:
   	p = SvPV(sv, len);
        keylen = BN_num_bits(key->n);
        if(len*8 != keylen)
  		croak("invalid size (%d), must match keysize(%d)", len*8, keylen);
        if(ix > 1 && !is_privkey(key))
                croak("need a private key.");
        rc = func[ix](len, p, out, key, RSA_NO_PADDING);
        if(rc < 0)
  		croak("crypto error...");
        XPUSHs(sv_2mortal(newSVpvn(out, rc)));


void
fingerprint(key)
    RSA *key
    PREINIT:
         char *x;
         char dig[SHA_DIGEST_LENGTH];
         int nlen, elen;
    PPCODE:
        nlen = BN_num_bytes(key->n);
        elen = BN_num_bytes(key->e);
        x = malloc(nlen + elen);
        if(!x)
  		croak("malloc error");
        BN_bn2bin(key->n, x);
        BN_bn2bin(key->e, &x[nlen]);
        run_sha1(dig, x, nlen+elen);	
        free(x);
        XPUSHs(sv_2mortal(newSVpvn(dig, SHA_DIGEST_LENGTH)));
         
void
sha1(sv)
  SV *sv
 PREINIT:
   char dig[SHA_DIGEST_LENGTH];
   char *p;
   STRLEN len;
 PPCODE:
   p = SvPV(sv, len);
   run_sha1(dig, p, len);
   XPUSHs(sv_2mortal(newSVpvn(dig, SHA_DIGEST_LENGTH)));
        
void
blowfish_encrypt(key, string)
	SV *key
        SV *string
      ALIAS:
        blowfish_decrypt = 1
      PREINIT:  
	BF_KEY *k;
        STRLEN len;
        char *p;
        char *out;
      PPCODE:
        k = malloc(sizeof(BF_KEY));
        if(!k)
  		croak("malloc failed.");
	p = SvPV(key, len);
        BF_set_key(k, len, p);
        p = SvPV(string, len);
        if(len % 8) {
          	free(k);
  		croak("illegal input length");
        }
        out = malloc(len + 7);
        if(!out) {
          free(k);
          croak("malloc failed.");
        }
        BF_cbc_encrypt(p, out, len, k, (unsigned char *) &k[0], (ix) ? BF_DECRYPT : BF_ENCRYPT);
        XPUSHs(sv_2mortal(newSVpvn(out, len)));
        free(k);
        free(out);
      
void
randombytes(nr)
  IV nr
  PREINIT:
  	char *p;
        int rc;
  PPCODE:
  	p = malloc(nr);
        if(!p)
  	   croak("malloc failed");
        rc = RAND_bytes(p, nr);
        if(rc != 1) {
           free(p);
  	   croak("RAND_bytes returned %d", rc);
        }
        XPUSHs(sv_2mortal(newSVpvn(p, nr)));
        free(p);



void
pseudorandombytes(nr)
  IV nr
  PREINIT:
  	char *p;
        int i, j;
        static int rrand_init = 0;
  PPCODE:
	if(!rrand_init) {
          char *q;
          if(!(q = malloc(sizeof(int)*INIT_LONGS)))
            croak("malloc");
          if(RAND_bytes(q, 20) != 1)
            croak("RAND_bytes");
          for(i = 0; i < (4*INIT_LONGS)-SHA_DIGEST_LENGTH; i+=20) {
            	run_sha1((char *)&q[i+SHA_DIGEST_LENGTH], (char *)&q[i], SHA_DIGEST_LENGTH);
            }
          lsgenrand((unsigned long *)q);
          free(q);
          rrand_init = 1;
        }
	j = (nr+3) & ~3;
	p = malloc(j);
        if(!p)
  	   croak("malloc failed");
        for(i = 0; i < j; i+=4) {
             *((int *)&p[i]) = genrand();
         }
        XPUSHs(sv_2mortal(newSVpvn(p, nr)));
        free(p);

