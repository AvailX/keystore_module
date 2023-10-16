package com.example.keystore;

import android.os.Build;
import android.text.TextUtils;
import android.util.Log;
import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringDef;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt.PromptInfo;

import com.example.keystore.PrefsStorage.ResultSet;
import com.example.keystore.cipherStorage.CipherStorage;
import com.example.keystore.cipherStorage.CipherStorage.DecryptionResult;
import com.example.keystore.cipherStorage.CipherStorage.EncryptionResult;
import com.example.keystore.decryptionHandler.DecryptionResultHandler;
import com.example.keystore.decryptionHandler.DecryptionResultHandlerProvider;
import com.example.keystore.cipherStorage.CipherStorageBase;
import com.example.keystore.cipherStorage.CipherStorageKeystoreAesCbc;
import com.example.keystore.cipherStorage.CipherStorageFacebookConceal;
import com.example.keystore.cipherStorage.CipherStorageKeystoreRsaEcb;
import com.example.keystore.exceptions.EmptyParameterException;
import com.example.keystore.exceptions.KeyStoreAccessException;
import com.example.keystore.exceptions.CryptoFailedException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

@SuppressWarnings({ "unused", "WeakerAccess", "SameParameterValue" })
public class KeyStoreModule {
  private static native String create(@NonNull final String alias,
      @NonNull final byte[] p_key,
      @NonNull final byte[] v_key,
      @Nullable final Map<String, Object> options,
      @NonNull final Context AContext);

  private static native String get(@NonNull final String alias,
      @Nullable final Map<String, Object> options, @NonNull final Context AContext, @NonNull final String key_type);

  private static native String update(@NonNull final String alias);

  private static native String delete(@NonNull final String alias);

  static {
    System.loadLibrary("availx_lib");
  }
  // region Constants
  public static final String KEYCHAIN_MODULE = "AVKeychainManager";
  public static final String FINGERPRINT_SUPPORTED_NAME = "Fingerprint";
  public static final String FACE_SUPPORTED_NAME = "Face";
  public static final String IRIS_SUPPORTED_NAME = "Iris";
  public static final String EMPTY_STRING = "";
  public static final String WARMING_UP_ALIAS = "warmingUp";

  private static final String LOG_TAG = KeyStoreModule.class.getSimpleName();

  @StringDef({ AccessControl.NONE, AccessControl.USER_PRESENCE, AccessControl.BIOMETRY_ANY,
      AccessControl.BIOMETRY_CURRENT_SET, AccessControl.DEVICE_PASSCODE, AccessControl.APPLICATION_PASSWORD,
      AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE, AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE })
  @interface AccessControl {
    String NONE = "None";
    String USER_PRESENCE = "UserPresence";
    String BIOMETRY_ANY = "BiometryAny";
    String BIOMETRY_CURRENT_SET = "BiometryCurrentSet";
    String DEVICE_PASSCODE = "DevicePasscode";
    String APPLICATION_PASSWORD = "ApplicationPassword";
    String BIOMETRY_ANY_OR_DEVICE_PASSCODE = "BiometryAnyOrDevicePasscode";
    String BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE = "BiometryCurrentSetOrDevicePasscode";
  }

  @interface AuthPromptOptions {
    String TITLE = "title";
    String SUBTITLE = "subtitle";
    String DESCRIPTION = "description";
    String CANCEL = "cancel";
  }

  /** Options mapping keys. */
  @interface Maps {
    String ACCESS_CONTROL = "accessControl";
    String ACCESS_GROUP = "accessGroup";
    String ACCESSIBLE = "accessible";
    String AUTH_PROMPT = "authenticationPrompt";
    String AUTH_TYPE = "authenticationType";
    String SERVICE = "service";
    String SECURITY_LEVEL = "securityLevel";
    String RULES = "rules";

    String USERNAME = "username";
    String PASSWORD = "password";
    String STORAGE = "storage";
  }

  /** Known error codes. */
  @interface Errors {
    String E_EMPTY_PARAMETERS = "E_EMPTY_PARAMETERS";
    String E_CRYPTO_FAILED = "E_CRYPTO_FAILED";
    String E_KEYSTORE_ACCESS_ERROR = "E_KEYSTORE_ACCESS_ERROR";
    String E_SUPPORTED_BIOMETRY_ERROR = "E_SUPPORTED_BIOMETRY_ERROR";
    /** Raised for unexpected errors. */
    String E_UNKNOWN_ERROR = "E_UNKNOWN_ERROR";
  }

  /** Supported ciphers. */
  public @interface KnownCiphers {
    /** Facebook conceal compatibility lib in use. */
    String FB = "FacebookConceal";
    /** AES encryption. */
    String AES = "KeystoreAESCBC";
    /** Biometric + RSA. */
    String RSA = "KeystoreRSAECB";
  }

  /** Secret manipulation rules. */
  @StringDef({ Rules.AUTOMATIC_UPGRADE, Rules.NONE })
  @interface Rules {
    String NONE = "none";
    String AUTOMATIC_UPGRADE = "automaticUpgradeToMoreSecuredStorage";
  }
  // endregion

  // region Members
  /** Name-to-instance lookup map. */
  private final Map<String, CipherStorage> cipherStorageMap = new HashMap<>();
  /** Shared preferences storage. */
  private final PrefsStorage prefsStorage;
  // endregion

  /** Default constructor. */
  public KeyStoreModule(@NonNull final Context AContext) {
    super();

    prefsStorage = new PrefsStorage(AContext);

    addCipherStorageToMap(new CipherStorageFacebookConceal(AContext));
    addCipherStorageToMap(new CipherStorageKeystoreAesCbc());

    // we have a references to newer api that will fail load of app classes in old
    // androids OS
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      addCipherStorageToMap(new CipherStorageKeystoreRsaEcb());
    }
  }

  /** Allow initialization in chain. */
  public static KeyStoreModule withWarming(@NonNull final Context AContext) {
    final KeyStoreModule instance = new KeyStoreModule(AContext);

    // force initialization of the crypto api in background thread
    final Thread warmingUp = new Thread(() -> instance.internalWarmingBestCipher(AContext), "keystore-warming-up");
    warmingUp.setDaemon(true);
    warmingUp.start();

    return instance;
  }

  /**
   * cipher (crypto api) warming up logic. force java load classes and
   * intializations.
   */
  private void internalWarmingBestCipher(Context AContext) {

    try {
      final long startTime = System.nanoTime();

      Log.v(KEYCHAIN_MODULE, "warming up started at " + startTime);
      final CipherStorageBase best = (CipherStorageBase) getCipherStorageForCurrentAPILevel(AContext);
      final Cipher instance = best.getCachedInstance();
      final boolean isSecure = best.supportsSecureHardware();
      final SecurityLevel requiredLevel = isSecure ? SecurityLevel.SECURE_HARDWARE : SecurityLevel.SECURE_SOFTWARE;
      best.generateKeyAndStoreUnderAlias(WARMING_UP_ALIAS, requiredLevel,false);
      best.getKeyStoreAndLoad();

      Log.v(KEYCHAIN_MODULE, "warming up takes: " +
          TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime) +
          " ms");
    } catch (Throwable ex) {
      Log.e(KEYCHAIN_MODULE, "warming up failed!", ex);
    }
  }
  // endregion

  public static Map<String, Object> constructOptions(String service, String authPromptTitle, String  authPromptSubTitle,
      String authPromptDesc, String authPromptCancel, String accessible, String accessControl, String storage, String securityLevel,
      String authType ) {
    final Map<String, String> authPrompt = new HashMap<>();
    authPrompt.put(AuthPromptOptions.TITLE, authPromptTitle);
    authPrompt.put(AuthPromptOptions.SUBTITLE, authPromptSubTitle);
    authPrompt.put(AuthPromptOptions.DESCRIPTION, authPromptDesc);
    authPrompt.put(AuthPromptOptions.CANCEL, authPromptCancel);

    final Map<String, Object> options = new HashMap<>();
    options.put(Maps.ACCESS_CONTROL, accessControl);
    options.put(Maps.ACCESSIBLE, accessible);
    options.put(Maps.AUTH_PROMPT, authPrompt);
    options.put(Maps.AUTH_TYPE, authType);
    options.put(Maps.SECURITY_LEVEL, securityLevel);
    options.put(Maps.SERVICE, service);
    options.put(Maps.STORAGE, storage);

    return options;

  }

  

  // region Tauri Methods
  /** This will be invoked from Tauri app */
  protected Map<String, String> setGenericPassword(@NonNull final String alias,
      @NonNull final byte[] p_key,
      @NonNull final byte[] v_key,
      @Nullable final Map<String, Object> options,
      @NonNull final Context AContext) {
    try {
      //throwIfEmptyLoginPassword(p_key, v_key)
      final SecurityLevel level = getSecurityLevelOrDefault(options);
      final CipherStorage storage = getSelectedStorage(options, AContext);
      final String accessControl = getAccessControlOrDefault(options);
      
      throwIfInsufficientLevel(storage, level);

      //make individual to p_key and v_key
      EncryptionResult result;
      //pass biometric to remove userPresence.
      if (accessControl == "BiometryCurrentSet"){
        System.out.println("biometric");
        result = storage.encrypt(alias, p_key, v_key, level,true);
      }else{
        System.out.println("Not biometric");
        result = storage.encrypt(alias, p_key, v_key, level,false);
      }
      prefsStorage.storeEncryptedEntry(alias, result);

      final Map<String, String> results = new HashMap<>();
      results.put(Maps.SERVICE, alias);
      results.put(Maps.STORAGE, storage.getCipherStorageName());

      System.out.println("SET RESULT");
      System.out.println(results);
      return results;
      /**
    } catch (EmptyParameterException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);

      final Map<String, String> error = new HashMap<>();
      error.put(Errors.E_EMPTY_PARAMETERS, String.valueOf(e));
      return error;
*/
    } catch (CryptoFailedException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);

      final Map<String, String> error = new HashMap<>();
      error.put(Errors.E_CRYPTO_FAILED, String.valueOf(e));
      return error;

    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      final Map<String, String> error = new HashMap<>();
      error.put(Errors.E_UNKNOWN_ERROR, fail.getMessage());
      return error;

    }
  }


  /** This will be invoked from Tauri app to check if biometry permissioned */
  public boolean checkBiometryPermission(Context AContext) {
    try {
      return DeviceAvailability.isPermissionsGranted(AContext);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);
      return false;
    }
  }



  /** This will be invoked from Tauri app to check biometric availability */
  public boolean checkBio(@NonNull final Context AContext) {
    try {
      return DeviceAvailability.isFingerprintEnabled(AContext);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);
      return false;
    }
  }

  public void setGenericPasswordForOptions(@Nullable final Map<String, Object> options,
      @NonNull final byte[] p_key,
      @NonNull final byte[] v_key, Context AContext) {
    final String service = getServiceOrDefault(options);
    setGenericPassword(service, p_key, v_key, options, AContext);
  }

  /** Get Cipher storage instance based on user provided options. */
  @NonNull
  private CipherStorage getSelectedStorage(@Nullable final Map<String, Object> options, Context AContext)
      throws CryptoFailedException {
    final String accessControl = getAccessControlOrDefault(options);
    final boolean useBiometry = getUseBiometry(accessControl);
    final String cipherName = getSpecificStorageOrDefault(options);

    CipherStorage result = null;

    if (null != cipherName) {
      result = getCipherStorageByName(cipherName);
    }

    // attempt to access none existing storage will force fallback logic.
    if (null == result) {
      result = getCipherStorageForCurrentAPILevel(useBiometry, AContext);
    }

    return new CipherStorageKeystoreRsaEcb();
  }

  /** This will be invoked from Tauri app */
  protected Map<String, Object> getGenericPassword(@NonNull final String alias,
      @Nullable final Map<String, Object> options, Context AContext,@NonNull final String key_type) {
    try {
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);
      System.out.println(key_type);
      if (resultSet == null) {
        Log.e(KEYCHAIN_MODULE, "No entry found for service: " + alias);

        final Map<String, Object> error = new HashMap<>();
        error.put(KEYCHAIN_MODULE, "No entry found for service: " + alias);
        return error;
      }

      final String storageName = resultSet.cipherStorageName;
      final String rules = getSecurityRulesOrDefault(options);
      final PromptInfo promptInfo = getPromptInfo(options);

      CipherStorage cipher = null;
      final String accessControl = getAccessControlOrDefault(options);
      // Only check for upgradable ciphers for FacebookConseal as that
      // is the only cipher that can be upgraded
      if (rules.equals(Rules.AUTOMATIC_UPGRADE) && storageName.equals(KnownCiphers.FB)) {
        // get the best storage
        
        final boolean useBiometry = getUseBiometry(accessControl);
        cipher = getCipherStorageForCurrentAPILevel(useBiometry, AContext);
      } else {
        cipher = getCipherStorageByName(storageName);
      }
      
      //linked hash map to be returned with results
       final Map<String, Object> credentials = new LinkedHashMap<>();
      
      if("avl-p".equals(key_type)){
        System.out.println("PRIVATE");
      final DecryptionResult decryptionResult; 
      if (accessControl == "BiometryCurrentSet") {
      decryptionResult=   decryptCredentials(alias, cipher, resultSet, rules, promptInfo,
          AContext, true,true);
      }else{
        decryptionResult=   decryptCredentials(alias, cipher, resultSet, rules, promptInfo,
          AContext, true,false);
      }
      //populate map
      credentials.put("Private Key", decryptionResult.p_key);
      credentials.put("Viewing Key", new byte[0]);
      }else if ("avl-v".equals(key_type)){
        System.out.println("VIEWING");
        
        final DecryptionResult decryptionResult;
        if (accessControl == "BiometryCurrentSet") {
          decryptionResult = decryptCredentials(alias, cipher, resultSet, rules, promptInfo,
            AContext, false, true);
        }else{
          decryptionResult = decryptCredentials(alias, cipher, resultSet, rules, promptInfo,
            AContext, false, false);
        }
        
        credentials.put("Private Key", decryptionResult.p_key);
       credentials.put("Viewing Key", decryptionResult.v_key);

      }

      System.out.println("CREDENTIALS");
      System.out.println(credentials);
      return credentials;
    } catch (KeyStoreAccessException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());
      System.out.println("FE1");
      final Map<String, Object> error = new HashMap<>();
      error.put(Errors.E_KEYSTORE_ACCESS_ERROR, String.valueOf(e));
      return error;

    } catch (CryptoFailedException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());
      System.out.println("FE3");
      final Map<String, Object> error = new HashMap<>();
      error.put(Errors.E_CRYPTO_FAILED, String.valueOf(e));
      return error;

    } catch (Throwable fail) {
      System.out.println("Fail 2");
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      final Map<String, Object> error = new HashMap<>();
      error.put(Errors.E_UNKNOWN_ERROR, fail.getMessage());
      return error;

    }
  }

  private static String[] makeNativeArray(Collection<String> collection) {
    String[] array = new String[collection.size()];
    collection.toArray(array);
    return array;
  }

  /**
   * public String[] getAllGenericPasswordServices() {
   * try {
   * Collection<String> services = doGetAllGenericPasswordServices();
   * return makeNativeArray(services);
   * } catch (KeyStoreAccessException e) {
   * promise.reject(Errors.E_KEYSTORE_ACCESS_ERROR, e);
   * }
   * }
   */

  private Collection<String> doGetAllGenericPasswordServices() throws KeyStoreAccessException {
    final Set<String> cipherNames = prefsStorage.getUsedCipherNames();

    Collection<CipherStorage> ciphers = new ArrayList<>(cipherNames.size());
    for (String storageName : cipherNames) {
      final CipherStorage cipherStorage = getCipherStorageByName(storageName);
      ciphers.add(cipherStorage);
    }

    Set<String> result = new HashSet<>();
    for (CipherStorage cipher : ciphers) {
      Set<String> aliases = cipher.getAllKeys();
      for (String alias : aliases) {
        if (!alias.equals(WARMING_UP_ALIAS)) {
          result.add(alias);
        }
      }
    }

    return result;
  }

  public void getGenericPasswordForOptions(@Nullable final Map<String, Object> options, Context AContext, @NonNull final String key_type) {
    final String service = getServiceOrDefault(options);
    getGenericPassword(service, options, AContext,key_type);
  }

  /** This will be invoked from Tauri app */
  protected boolean resetGenericPassword(@NonNull final String alias) {
    try {
      // First we clean up the cipher storage (using the cipher storage that was used
      // to store the entry)
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);

      if (resultSet != null) {
        final CipherStorage cipherStorage = getCipherStorageByName(resultSet.cipherStorageName);

        if (cipherStorage != null) {
          cipherStorage.removeKey(alias);
        }
      }
      // And then we remove the entry in the shared preferences
      prefsStorage.removeEntry(alias);

      System.out.println("RESET PASSWORD TEST true");
      return true;
    } catch (KeyStoreAccessException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

      // promise.reject(Errors.E_KEYSTORE_ACCESS_ERROR, e);
      return false;
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      // promise.reject(Errors.E_UNKNOWN_ERROR, fail);
      return false;
    }
  }

  public void resetGenericPasswordForOptions(@Nullable final Map<String, Object> options) {
    final String service = getServiceOrDefault(options);
    resetGenericPassword(service);
  }

  /**
   * public void hasInternetCredentialsForServer(@NonNull final String server) {
   * final String alias = getAliasOrDefault(server);
   * 
   * final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);
   * 
   * if (resultSet == null) {
   * Log.e(KEYCHAIN_MODULE, "No entry found for service: " + alias);
   * promise.resolve(false);
   * return;
   * }
   * 
   * final WritableMap results = Arguments.createMap();
   * results.putString(Maps.SERVICE, alias);
   * results.putString(Maps.STORAGE, resultSet.cipherStorageName);
   * 
   * promise.resolve(results);
   * }
   */

  /**
   * public void setInternetCredentialsForServer(@NonNull final String server,
   * 
   * @NonNull final String username,
   * @NonNull final String password,
   * @Nullable final ReadableMap options,
   * @NonNull final Promise promise) {
   *          setGenericPassword(server, username, password, options, promise);
   *          }
   */

  /**
   * public void getInternetCredentialsForServer(@NonNull final String server,
   * 
   * @Nullable final ReadableMap options,
   * @NonNull final Promise promise) {
   *          getGenericPassword(server, options, promise);
   *          }
   */

  /**
   * public void resetInternetCredentialsForServer(@NonNull final String server,
   * 
   * @NonNull final Promise promise) {
   *          resetGenericPassword(server, promise);
   *          }
   */

  public String getSupportedBiometryType(Context AContext) {
    try {
      String reply = null;

      if (!DeviceAvailability.isStrongBiometricAuthAvailable(AContext)) {
        reply = null;
      } else {
        if (isFingerprintAuthAvailable(AContext)) {
          reply = FINGERPRINT_SUPPORTED_NAME;
        } else if (isFaceAuthAvailable(AContext)) {
          reply = FACE_SUPPORTED_NAME;
        } else if (isIrisAuthAvailable(AContext)) {
          reply = IRIS_SUPPORTED_NAME;
        }
      }

      return reply;
    } catch (Exception e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);
      return (Errors.E_SUPPORTED_BIOMETRY_ERROR + e);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);
      return (Errors.E_UNKNOWN_ERROR + fail);
    }
  }

  public String getSecurityLevel(@Nullable final Map<String, Object> options, Context AContext) {
    // DONE (olku): if forced biometry than we should return security level =
    // HARDWARE if it supported
    final String accessControl = getAccessControlOrDefault(options);
    final boolean useBiometry = getUseBiometry(accessControl);

    return getSecurityLevel(useBiometry, AContext).name();
  }
  // endregion

  // region Helpers

  /** Get service value from options. */
  @NonNull
  private static String getServiceOrDefault(@Nullable final Map<String, Object> options) {
    String service = null;

    if (null != options && options.containsKey(Maps.SERVICE)) {
      service = options.get(Maps.SERVICE).toString();
    }

    return getAliasOrDefault(service);
  }

  /** Get automatic secret manipulation rules, default: No upgrade. */
  @Rules
  @NonNull
  private static String getSecurityRulesOrDefault(@Nullable final Map<String, Object> options) {
    return getSecurityRulesOrDefault(options, Rules.NONE);
  }

  /** Get automatic secret manipulation rules. */
  @Rules
  @NonNull
  private static String getSecurityRulesOrDefault(@Nullable final Map<String, Object> options,
      @Rules @NonNull final String rule) {
    String rules = null;

    if (null != options && options.containsKey(Maps.RULES)) {
      rules = options.get(Maps.RULES).toString();
    }

    if (null == rules)
      return rule;

    return rules;
  }

  /** Extract user specified storage from options. */
  @KnownCiphers
  @Nullable
  private static String getSpecificStorageOrDefault(@Nullable final Map<String, Object> options) {
    String storageName = null;

    if (null != options && options.containsKey(Maps.STORAGE)) {
      storageName = options.get(Maps.STORAGE).toString();
    }

    return storageName;
  }

  /**
   * Get access control value from options or fallback to
   * {@link AccessControl#NONE}.
   */
  @AccessControl
  @NonNull
  private static String getAccessControlOrDefault(@Nullable final Map<String, Object> options) {
    return getAccessControlOrDefault(options, AccessControl.NONE);
  }

  /** Get access control value from options or fallback to default. */
  @AccessControl
  @NonNull
  private static String getAccessControlOrDefault(@Nullable final Map<String, Object> options,
      @AccessControl @NonNull final String fallback) {
    String accessControl = null;

    if (null != options && options.containsKey(Maps.ACCESS_CONTROL)) {
      accessControl = options.get(Maps.ACCESS_CONTROL).toString();
    }

    if (null == accessControl)
      return fallback;

    return accessControl;
  }

  /**
   * Get security level from options or fallback {@link SecurityLevel#ANY} value.
   */
  @NonNull
  private static SecurityLevel getSecurityLevelOrDefault(@Nullable final Map<String, Object> options) {
    return getSecurityLevelOrDefault(options, SecurityLevel.ANY.name());
  }

  /** Get security level from options or fallback to default value. */
  @NonNull
  private static SecurityLevel getSecurityLevelOrDefault(@Nullable final Map<String, Object> options,
      @NonNull final String fallback) {
    String minimalSecurityLevel = null;

    System.out.println( options);

    if (null != options && options.containsKey(Maps.SECURITY_LEVEL)) {
      minimalSecurityLevel = options.get(Maps.SECURITY_LEVEL).toString();
    }

    if (null == minimalSecurityLevel)
      minimalSecurityLevel = fallback;

    System.out.println("SECURITY LEVEL TEST " + minimalSecurityLevel);
   
    return SecurityLevel.valueOf(minimalSecurityLevel);
  }
  // endregion

  // region Implementation

  /** Is provided access control string matching biometry use request? */
  public static boolean getUseBiometry(@AccessControl @Nullable final String accessControl) {
    return AccessControl.BIOMETRY_ANY.equals(accessControl)
        || AccessControl.BIOMETRY_CURRENT_SET.equals(accessControl)
        || AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE.equals(accessControl)
        || AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE.equals(accessControl);
  }

  private void addCipherStorageToMap(@NonNull final CipherStorage cipherStorage) {
    cipherStorageMap.put(cipherStorage.getCipherStorageName(), cipherStorage);
  }

  /** Extract user specified prompt info from options. */
  @NonNull
  private static PromptInfo getPromptInfo(@Nullable final Map<String, Object> options) {
    final Map<String, Object> promptInfoOptionsMap = (options != null && options.containsKey(Maps.AUTH_PROMPT))
        ? (Map<String, Object>) options.get(Maps.AUTH_PROMPT)
        : null;

    final String accessControl = getAccessControlOrDefault(options);     

    final PromptInfo.Builder promptInfoBuilder = new PromptInfo.Builder();
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.containsKey(AuthPromptOptions.TITLE)) {
      String promptInfoTitle = promptInfoOptionsMap.get(AuthPromptOptions.TITLE).toString();
      promptInfoBuilder.setTitle(promptInfoTitle);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.containsKey(AuthPromptOptions.SUBTITLE)) {
      String promptInfoSubtitle = promptInfoOptionsMap.get(AuthPromptOptions.SUBTITLE).toString();
      promptInfoBuilder.setSubtitle(promptInfoSubtitle);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.containsKey(AuthPromptOptions.DESCRIPTION)) {
      String promptInfoDescription = promptInfoOptionsMap.get(AuthPromptOptions.DESCRIPTION).toString();
      promptInfoBuilder.setDescription(promptInfoDescription);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.containsKey(AuthPromptOptions.CANCEL) && accessControl.equals(AccessControl.BIOMETRY_CURRENT_SET)) {
      String promptInfoNegativeButton = promptInfoOptionsMap.get(AuthPromptOptions.CANCEL).toString();
      promptInfoBuilder.setNegativeButtonText(promptInfoNegativeButton);
    }

    /*
     * PromptInfo is only used in Biometric-enabled RSA storage and can only be
     * unlocked by a strong biometric
     */

     if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R){
      promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
     }else if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P){
      promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
     }else{
      promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK);
     }

    /*
     * Bypass confirmation to avoid KeyStore unlock timeout being exceeded when
     * using passive biometrics
     */
    promptInfoBuilder.setConfirmationRequired(false);

    final PromptInfo promptInfo = promptInfoBuilder.build();

    return promptInfo;
  }

  /**
   * Extract credentials from current storage. In case if current storage is not
   * matching
   * results set then executed migration.
   */
  @NonNull
  private DecryptionResult decryptCredentials(@NonNull final String alias,
      @NonNull final CipherStorage current,
      @NonNull final ResultSet resultSet,
      @Rules @NonNull final String rules,
      @NonNull final PromptInfo promptInfo,
      @NonNull final Context AContext,
      @NonNull final boolean key_type,
      @NonNull final boolean biometric)
      throws CryptoFailedException, KeyStoreAccessException {
    final String storageName = resultSet.cipherStorageName;

    // The encrypted data is encrypted using the current CipherStorage, so we just
    // decrypt and return
    if (storageName.equals(current.getCipherStorageName())) {
      return decryptToResult(alias, current, resultSet, promptInfo, AContext, key_type,biometric);
    }

    // The encrypted data is encrypted using an older CipherStorage, so we need to
    // decrypt the data first,
    // then encrypt it using the current CipherStorage, then store it again and
    // return
    final CipherStorage oldStorage = getCipherStorageByName(storageName);
    if (null == oldStorage) {
      throw new KeyStoreAccessException("Wrong cipher storage name '" + storageName + "' or cipher not available");
    }

    // decrypt using the older cipher storage
    final DecryptionResult decryptionResult = decryptToResult(alias, oldStorage, resultSet, promptInfo, AContext, key_type,biometric);

    if (Rules.AUTOMATIC_UPGRADE.equals(rules)) {
      try {
        // encrypt using the current cipher storage
        migrateCipherStorage(alias, current, oldStorage, decryptionResult,biometric);
      } catch (CryptoFailedException e) {
        Log.w(KEYCHAIN_MODULE, "Migrating to a less safe storage is not allowed. Keeping the old one");
      }
    }

    return decryptionResult;
  }

  /** Try to decrypt with provided storage. */
  @NonNull
  private DecryptionResult decryptToResult(@NonNull final String alias,
      @NonNull final CipherStorage storage,
      @NonNull final ResultSet resultSet,
      @NonNull final PromptInfo promptInfo,
      @NonNull final Context AContext,
      @NonNull final boolean key_type,
     @NonNull final boolean biometric)
      throws CryptoFailedException {
    final DecryptionResultHandler handler = getInteractiveHandler(storage, promptInfo, AContext);
    
    
    storage.decrypt(handler, alias, resultSet.p_key, resultSet.v_key, SecurityLevel.ANY, key_type,biometric);

    CryptoFailedException.reThrowOnError(handler.getError());

    if (null == handler.getResult()) {
      throw new CryptoFailedException("No decryption results and no error. Something deeply wrong!");
    }

    return handler.getResult();
  }

  /**
   * Get instance of handler that resolves access to the keystore on system
   * request.
   */
  @NonNull
  protected DecryptionResultHandler getInteractiveHandler(@NonNull final CipherStorage current,
      @NonNull final PromptInfo promptInfo, @NonNull final Context AContext) {

    return DecryptionResultHandlerProvider.getHandler(AContext, current, promptInfo);
  }

  /** Remove key from old storage and add it to the new storage. */
  /* package */ void migrateCipherStorage(@NonNull final String service,
      @NonNull final CipherStorage newCipherStorage,
      @NonNull final CipherStorage oldCipherStorage,
      @NonNull final DecryptionResult decryptionResult,
      @NonNull final boolean biometric)
      throws KeyStoreAccessException, CryptoFailedException {

    // don't allow to degrade security level when transferring, the new
    // storage should be as safe as the old one.
    final EncryptionResult encryptionResult = newCipherStorage.encrypt(
        service, decryptionResult.p_key, decryptionResult.v_key,
        decryptionResult.getSecurityLevel(),biometric);

    // store the encryption result
    prefsStorage.storeEncryptedEntry(service, encryptionResult);

    // clean up the old cipher storage
    oldCipherStorage.removeKey(service);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level
   * that is
   * lower than or equal to the current API level
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel(Context AContext) throws CryptoFailedException {
    return getCipherStorageForCurrentAPILevel(true, AContext);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level
   * that is
   * lower than or equal to the current API level. Parameter allow to reduce
   * level.
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel(final boolean useBiometry, Context AContext)
      throws CryptoFailedException {
    final int currentApiLevel = Build.VERSION.SDK_INT;
    final boolean isBiometry = useBiometry
        || (isFingerprintAuthAvailable(AContext) || isFaceAuthAvailable(AContext) || isIrisAuthAvailable(AContext));
    CipherStorage foundCipher = null;
    
    System.out.println("ISBIOMETRY "+isBiometry);
    
    for (CipherStorage variant : cipherStorageMap.values()) {
      Log.d(KEYCHAIN_MODULE, "Probe cipher storage: " + variant.getClass().getSimpleName());

      // Is the cipherStorage supported on the current API level?
      final int minApiLevel = variant.getMinSupportedApiLevel();
      final int capabilityLevel = variant.getCapabilityLevel();
      final boolean isSupportedApi = (minApiLevel <= currentApiLevel);

      // API not supported
      if (!isSupportedApi)
        continue;

      // Is the API level better than the one we previously selected (if any)?
      if (foundCipher != null && capabilityLevel < foundCipher.getCapabilityLevel())
        continue;

      // if biometric supported but not configured properly than skip
      if (variant.isBiometrySupported() && !isBiometry)
        continue;

      // remember storage with the best capabilities
      foundCipher = variant;
    }

    if (foundCipher == null) {
      throw new CryptoFailedException("Unsupported Android SDK " + Build.VERSION.SDK_INT);
    }

    Log.d(KEYCHAIN_MODULE, "Selected storage: " + foundCipher.getClass().getSimpleName());
    System.out.println(KEYCHAIN_MODULE + "Selected storage: " + foundCipher.getClass().getSimpleName());

    if(foundCipher == new CipherStorageKeystoreAesCbc()){
      foundCipher = new CipherStorageKeystoreRsaEcb();
    }
    
    return foundCipher;
  }

  /** Throw exception in case of empty credentials providing. */
  public static void throwIfEmptyLoginPassword(@Nullable final String username,
      @Nullable final String password)
      throws EmptyParameterException {
    if (TextUtils.isEmpty(username) || TextUtils.isEmpty(password)) {
      
      throw new EmptyParameterException("you passed empty or null username/password");
    }
  }

  /**
   * Throw exception if required security level does not match storage provided
   * security level.
   */
  public static void throwIfInsufficientLevel(@NonNull final CipherStorage storage,
      @NonNull final SecurityLevel level)
      throws CryptoFailedException {
    if (storage.securityLevel().satisfiesSafetyThreshold(level)) {
      return;
    }

    throw new CryptoFailedException(
        String.format(
            "Cipher Storage is too weak. Required security level is: %s, but only %s is provided",
            level.name(),
            storage.securityLevel().name()));
  }

  /**
   * Extract cipher by it unique name.
   * {@link CipherStorage#getCipherStorageName()}.
   */
  @Nullable
  /* package */ CipherStorage getCipherStorageByName(@KnownCiphers @NonNull final String knownName) {
    return cipherStorageMap.get(knownName);
  }

  /** True - if fingerprint hardware available and configured, otherwise false. */
  /* package */ boolean isFingerprintAuthAvailable(Context AContext) {
    return DeviceAvailability.isStrongBiometricAuthAvailable(AContext)
        && DeviceAvailability.isFingerprintAuthAvailable(AContext);
  }

  /**
   * True - if face recognition hardware available and configured, otherwise
   * false.
   */
  /* package */ boolean isFaceAuthAvailable(Context AContext) {
    return DeviceAvailability.isStrongBiometricAuthAvailable(AContext)
        && DeviceAvailability.isFaceAuthAvailable(AContext);
  }

  /**
   * True - if iris recognition hardware available and configured, otherwise
   * false.
   */
  /* package */ boolean isIrisAuthAvailable(Context AContext) {
    return DeviceAvailability.isStrongBiometricAuthAvailable(AContext)
        && DeviceAvailability.isIrisAuthAvailable(AContext);
  }

  /** Is secured hardware a part of current storage or not. */
  /* package */ boolean isSecureHardwareAvailable(Context AContext) {
    try {
      return getCipherStorageForCurrentAPILevel(AContext).supportsSecureHardware();
    } catch (CryptoFailedException e) {
      return false;
    }
  }

  /** Resolve storage to security level it provides. */
  @NonNull
  private SecurityLevel getSecurityLevel(final boolean useBiometry, Context AContext) {
    try {
      final CipherStorage storage = getCipherStorageForCurrentAPILevel(useBiometry, AContext);

      if (!storage.securityLevel().satisfiesSafetyThreshold(SecurityLevel.SECURE_SOFTWARE)) {
        return SecurityLevel.ANY;
      }

      if (storage.supportsSecureHardware()) {
        return SecurityLevel.SECURE_HARDWARE;
      }

      return SecurityLevel.SECURE_SOFTWARE;
    } catch (CryptoFailedException e) {
      Log.w(KEYCHAIN_MODULE, "Security Level Exception: " + e.getMessage(), e);

      return SecurityLevel.ANY;
    }
  }

  @NonNull
  private static String getAliasOrDefault(@Nullable final String service) {
    return service == null ? EMPTY_STRING : service;
  }
  // endregion

}
