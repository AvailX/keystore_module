package com.example.keystore.decryptionHandler;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.keystore.cipherStorage.CipherStorage.DecryptionContext;
import com.example.keystore.cipherStorage.CipherStorage.DecryptionResult;
public interface DecryptionResultHandler {
  /** Ask user for interaction, often its unlock of keystore by biometric data providing. */
  void askAccessPermissions(@NonNull final DecryptionContext context);

  /**
   *
   */
  void onDecrypt(@Nullable final DecryptionResult decryptionResult, @Nullable final Throwable error);

  /** Get reference on results. */
  @Nullable
  DecryptionResult getResult();

  /** Get reference on capture error. */
  @Nullable
  Throwable getError();

  /** Block thread and wait for any result of execution. */
  void waitResult();
}