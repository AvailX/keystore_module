package com.example.keystore.decryptionHandler;

import android.os.Build;
import android.content.Context;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

import com.example.keystore.cipherStorage.CipherStorage;

import java.util.Arrays;


public class DecryptionResultHandlerProvider {
  private static final String ONE_PLUS_BRAND = "oneplus";
  private static final String[] ONE_PLUS_MODELS_WITHOUT_BIOMETRIC_BUG = {
    "A0001", // OnePlus One
    "ONE A2001", "ONE A2003", "ONE A2005", // OnePlus 2
    "ONE E1001", "ONE E1003", "ONE E1005", // OnePlus X
    "ONEPLUS A3000", "ONEPLUS SM-A3000", "ONEPLUS A3003", // OnePlus 3
    "ONEPLUS A3010", // OnePlus 3T
    "ONEPLUS A5000", // OnePlus 5
    "ONEPLUS A5010", // OnePlus 5T
    "ONEPLUS A6000", "ONEPLUS A6003" // OnePlus 6
  };

  private static boolean hasOnePlusBiometricBug() {
    return Build.BRAND.toLowerCase().equals(ONE_PLUS_BRAND) &&
      !Arrays.asList(ONE_PLUS_MODELS_WITHOUT_BIOMETRIC_BUG).contains(Build.MODEL);
  }

  public static DecryptionResultHandler getHandler(@NonNull Context AContext,
                                                   @NonNull final CipherStorage storage,
                                                   @NonNull final BiometricPrompt.PromptInfo promptInfo) {
    if (storage.isBiometrySupported()) {
      if (hasOnePlusBiometricBug()) {
        return new DecryptionResultHandlerInteractiveBiometricManualRetry(AContext, storage, promptInfo);
      }

      return new DecryptionResultHandlerInteractiveBiometric(AContext, storage, promptInfo);
    }

    return new DecryptionResultHandlerNonInteractive();
  }
}
