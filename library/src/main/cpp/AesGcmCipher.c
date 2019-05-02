#include <jni.h>
#include <stdlib.h>
#include <openssl/cipher.h>

struct STREAMING_GCM_CTX {
    EVP_CIPHER_CTX gcm_ctx;
    int encrypt;
};

void STREAMING_GCM_free(struct STREAMING_GCM_CTX *ctx) {
    EVP_CIPHER_CTX_cleanup(&ctx->gcm_ctx);
    free(ctx);
}

JNIEXPORT jlong JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_initializeCipher
  (JNIEnv *env, jobject obj, jboolean encrypt, jbyteArray key, jint keyLength, jbyteArray iv)
{
    jbyte* keyPointer = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte* ivPointer  = (*env)->GetByteArrayElements(env, iv, NULL);

    const EVP_CIPHER *cipher;

    if (keyLength == 16) { 
        cipher = EVP_aes_128_gcm();
    } else if (keyLength == 32) {
        cipher = EVP_aes_256_gcm();
    } else {
        (*env)->ReleaseByteArrayElements(env, key, keyPointer, 0);
        (*env)->ReleaseByteArrayElements(env, iv, ivPointer, 0);

        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Only 16 or 32 byte keys are supported");
        return 0;
    }

    struct STREAMING_GCM_CTX *ctx = malloc(sizeof(struct STREAMING_GCM_CTX));

    if (ctx == NULL) {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Malloc failed!");
        return 0;
    }

    EVP_CIPHER_CTX_init(&ctx->gcm_ctx);
    ctx->encrypt = encrypt;

    if (!EVP_CipherInit_ex(&ctx->gcm_ctx, cipher, NULL, NULL, NULL, encrypt ? 1 : 0)) {
        free(ctx);
        (*env)->ReleaseByteArrayElements(env, key, keyPointer, 0);
        (*env)->ReleaseByteArrayElements(env, iv, ivPointer, 0);

        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Failed to initialize cipher context");
        return 0;
    }

    if (!EVP_CIPHER_CTX_ctrl(&ctx->gcm_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, 0) ||
        !EVP_CipherInit_ex(&ctx->gcm_ctx, NULL, NULL, (uint8_t *)keyPointer, (uint8_t *)ivPointer, -1))
    {
        STREAMING_GCM_free(ctx);
        (*env)->ReleaseByteArrayElements(env, key, keyPointer, 0);
        (*env)->ReleaseByteArrayElements(env, iv, ivPointer, 0);

        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Failed to configure cipher context");
        return 0;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyPointer, 0);
    (*env)->ReleaseByteArrayElements(env, iv, ivPointer, 0);
    return (jlong)ctx;
}

JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_update
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray input, jint inputOffset, jint inputLength, jbyteArray output, jint outputOffset, jint outputLength)
{
    struct STREAMING_GCM_CTX *ctx = (struct STREAMING_GCM_CTX*)ctxPointer;

    jbyte* inputPointer  = (*env)->GetByteArrayElements(env, input, NULL);
    jbyte* outputPointer = (*env)->GetByteArrayElements(env, output, NULL);

    if (!EVP_CipherUpdate(&ctx->gcm_ctx,
                          (uint8_t *)(outputPointer + outputOffset), &outputLength,
                          (uint8_t *)(inputPointer + inputOffset), inputLength))
    {
        (*env)->ReleaseByteArrayElements(env, input, inputPointer, 0);
        (*env)->ReleaseByteArrayElements(env, output, outputPointer, 0);

        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Cipher update failed!");
    }

    (*env)->ReleaseByteArrayElements(env, input, inputPointer, 0);
    (*env)->ReleaseByteArrayElements(env, output, outputPointer, 0);
}

JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_updateAAD
        (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray input, jint inputOffset, jint inputLength)
{
    struct STREAMING_GCM_CTX *ctx = (struct STREAMING_GCM_CTX*)ctxPointer;

    jbyte* inputPointer  = (*env)->GetByteArrayElements(env, input, NULL);
    int unused;

    if (!EVP_CipherUpdate(&ctx->gcm_ctx, NULL, &unused, (uint8_t *)(inputPointer + inputOffset), inputLength)) {
        (*env)->ReleaseByteArrayElements(env, input, inputPointer, 0);
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Cipher AAD update failed!");
        return;
    }

    (*env)->ReleaseByteArrayElements(env, input, inputPointer, 0);
}

JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_finishEncrypt
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray output, jint tagLength)
{
  struct STREAMING_GCM_CTX *ctx = (struct STREAMING_GCM_CTX*)ctxPointer;

  if (!ctx->encrypt) {
      (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "finishEncrypt called for decrypt context!");
      return;
  }

  jbyte* outputPointer = (*env)->GetByteArrayElements(env, output, NULL);

  int len;

  if (!EVP_CipherFinal_ex(&ctx->gcm_ctx, (uint8_t *)outputPointer, &len) ||
      len != 0                                      ||
      !EVP_CIPHER_CTX_ctrl(&ctx->gcm_ctx, EVP_CTRL_AEAD_GET_TAG, tagLength, (uint8_t *)outputPointer))
  {
      (*env)->ReleaseByteArrayElements(env, output, outputPointer, 0);
      (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "Cipher doFinal failed!");
      return;
  }

  (*env)->ReleaseByteArrayElements(env, output, outputPointer, 0);
}

JNIEXPORT jboolean JNICALL Java_org_signal_aesgcmprovider_AesGcmCipher_finishDecrypt
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray tag, jint tagLength)
{
    struct STREAMING_GCM_CTX *ctx = (struct STREAMING_GCM_CTX*)ctxPointer;

    if (ctx->encrypt) {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"), "finishDecrypt called for encrpyt context!");
        return JNI_FALSE;
    }

    jbyte* tagPointer = (*env)->GetByteArrayElements(env, tag, NULL);

    int len;
    int result = EVP_CIPHER_CTX_ctrl(&ctx->gcm_ctx, EVP_CTRL_AEAD_SET_TAG, tagLength, (uint8_t *)tagPointer) &&
                 EVP_CipherFinal_ex(&ctx->gcm_ctx, NULL, &len)                                               &&
                 len == 0;

    (*env)->ReleaseByteArrayElements(env, tag, tagPointer, 0);

    if (result != 0) return JNI_TRUE;
    else             return JNI_FALSE;
}

JNIEXPORT void JNICALL Java_org_signal_aesgcmprovider_AesGcmCipher_destroy
        (JNIEnv *env, jobject obj, jlong ctxPointer)
{
    struct STREAMING_GCM_CTX *ctx = (struct STREAMING_GCM_CTX*)ctxPointer;
    STREAMING_GCM_free(ctx);
}

