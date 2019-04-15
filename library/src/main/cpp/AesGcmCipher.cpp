#include <jni.h>
#include <cstdlib>
#include <openssl/cipher.h>

extern "C" JNIEXPORT jlong JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_initializeCipher
  (JNIEnv *env, jobject obj, jboolean encrypt, jbyteArray key, jint keyLength, jbyteArray iv)
{
    jbyte* keyPointer = env->GetByteArrayElements(key, nullptr);
    jbyte* ivPointer  = env->GetByteArrayElements(iv, nullptr);

    const EVP_CIPHER *cipher;

    if (keyLength == 16) { 
        cipher = EVP_aes_128_gcm();
    } else if (keyLength == 32) {
        cipher = EVP_aes_256_gcm();
    } else {
        env->ReleaseByteArrayElements(key, keyPointer, 0);
        env->ReleaseByteArrayElements(iv, ivPointer, 0);

        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Only 16 or 32 byte keys are supported");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    ctx->encrypt = encrypt ? 1 : 0;

    if (!EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, encrypt ? 1 : 0)) {
        free(ctx);
        env->ReleaseByteArrayElements(key, keyPointer, 0);
        env->ReleaseByteArrayElements(iv, ivPointer, 0);

        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Failed to initialize cipher context");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, 0) ||
        !EVP_CipherInit_ex(ctx, nullptr, nullptr, (uint8_t *)keyPointer, (uint8_t *)ivPointer, -1))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        free(ctx);
        env->ReleaseByteArrayElements(key, keyPointer, 0);
        env->ReleaseByteArrayElements(iv, ivPointer, 0);

        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Failed to configure cipher context");
    }

    env->ReleaseByteArrayElements(key, keyPointer, 0);
    env->ReleaseByteArrayElements(iv, ivPointer, 0);
    return (jlong)ctx;
}

extern "C" JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_update
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray input, jint inputOffset, jint inputLength, jbyteArray output, jint outputOffset, jint outputLength)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)ctxPointer;

    jbyte* inputPointer  = env->GetByteArrayElements(input, nullptr);
    jbyte* outputPointer = env->GetByteArrayElements(output, nullptr);

    if (!EVP_CipherUpdate(ctx, (uint8_t *)(outputPointer + outputOffset), &outputLength,
                               (uint8_t *)(inputPointer + inputOffset), inputLength))
    {
        env->ReleaseByteArrayElements(input, inputPointer, 0);
        env->ReleaseByteArrayElements(output, outputPointer, 0);

        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Cipher update failed!");
    }

    env->ReleaseByteArrayElements(input, inputPointer, 0);
    env->ReleaseByteArrayElements(output, outputPointer, 0);
}

extern "C" JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_updateAAD
        (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray input, jint inputOffset, jint inputLength)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)ctxPointer;

    jbyte* inputPointer  = env->GetByteArrayElements(input, nullptr);
    int unused;

    if (!EVP_CipherUpdate(ctx, nullptr, &unused, (uint8_t *)(inputPointer + inputOffset), inputLength)) {
        env->ReleaseByteArrayElements(input, inputPointer, 0);
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Cipher AAD update failed!");
    }

    env->ReleaseByteArrayElements(input, inputPointer, 0);
}

extern "C" JNIEXPORT void JNICALL
Java_org_signal_aesgcmprovider_AesGcmCipher_finishEncrypt
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray output, jint tagLength)
{
  EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)ctxPointer;

  jbyte* outputPointer = env->GetByteArrayElements(output, nullptr);

  int len;

  if (!EVP_CipherFinal_ex(ctx, (uint8_t *)outputPointer, &len) ||
      len != 0                                      ||
      !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLength, (uint8_t *)outputPointer))
  {
      env->ReleaseByteArrayElements(output, outputPointer, 0);

      env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "Cipher doFinal failed!");
  }

  env->ReleaseByteArrayElements(output, outputPointer, 0);
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_signal_aesgcmprovider_AesGcmCipher_finishDecrypt
  (JNIEnv *env, jobject obj, jlong ctxPointer, jbyteArray tag, jint tagLength)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)ctxPointer;

    jbyte* tagPointer = env->GetByteArrayElements(tag, nullptr);

    int len;
    int result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLength, (uint8_t *)tagPointer) &&
                 EVP_CipherFinal_ex(ctx, nullptr, &len)                                            &&
                 len == 0;

    env->ReleaseByteArrayElements(tag, tagPointer, 0);

    if (result != 0) return JNI_TRUE;
    else             return JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL Java_org_signal_aesgcmprovider_AesGcmCipher_destroy
        (JNIEnv *env, jobject obj, jlong ctxPointer)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)ctxPointer;

    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
}

