package com.example.keystore.decryptionHandler;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.keystore.cipherStorage.CipherStorage.DecryptionContext;
import com.example.keystore.cipherStorage.CipherStorage.DecryptionResult;
import com.example.keystore.exceptions.CryptoFailedException;

public class DecryptionResultHandlerNonInteractive implements DecryptionResultHandler{
  private DecryptionResult result;
  private Throwable error;

  @Override
  public void askAccessPermissions(@NonNull final DecryptionContext context) {
    final CryptoFailedException failure = new CryptoFailedException(
      "Non interactive decryption mode.");

    onDecrypt(null, failure);
  }

  @Override
  public void onDecrypt(@Nullable final DecryptionResult decryptionResult,
                        @Nullable final Throwable error) {
    this.result = decryptionResult;
    this.error = error;
  }

  @Nullable
  @Override
  public DecryptionResult getResult() {
    return result;
  }

  @Nullable
  @Override
  public Throwable getError() {
    return error;
  }

  @Override
  public void waitResult() {
    /* do nothing, expected synchronized call in one thread */
  }
}


