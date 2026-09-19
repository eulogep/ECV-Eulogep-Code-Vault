import Foundation
import LocalAuthentication
import Security

// ecv-auth: macOS authentication helper for Eulogep Code Vault.
//
//   ecv-auth enroll <account> <reason>   authenticate, create a device secret, store it, print it (base64)
//   ecv-auth unlock <account> <reason>   authenticate, print the stored device secret (base64)
//   ecv-auth confirm <reason>            authenticate only (used for step-up approvals)
//   ecv-auth remove <account>            delete the stored secret
//
// Exit codes: 0 ok, 1 error, 2 authentication refused, 3 authentication unavailable.
//
// v0.1 limitation: the secret sits in the login Keychain and Touch ID is a
// user-presence gate in front of it. Binding the key to the Secure Enclave
// requires a signed build with keychain entitlements (see docs/THREAT_MODEL.md).

let service = "dev.eulogep.ecv"

func die(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func authenticate(reason: String) {
    let context = LAContext()
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
        die("authentication unavailable: \(policyError?.localizedDescription ?? "unknown reason")", code: 3)
    }
    let done = DispatchSemaphore(value: 0)
    var approved = false
    var failure: Error?
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, error in
        approved = ok
        failure = error
        done.signal()
    }
    done.wait()
    if !approved {
        die("authentication refused: \(failure?.localizedDescription ?? "cancelled")", code: 2)
    }
}

func baseQuery(account: String) -> [String: Any] {
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

func storeSecret(account: String, secret: Data) {
    SecItemDelete(baseQuery(account: account) as CFDictionary)
    var attributes = baseQuery(account: account)
    attributes[kSecValueData as String] = secret
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    if status != errSecSuccess {
        die("keychain write failed (OSStatus \(status))")
    }
}

func loadSecret(account: String) -> Data {
    var query = baseQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else {
        die("no device secret for '\(account)' (OSStatus \(status))")
    }
    return data
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    die("usage: ecv-auth enroll|unlock|confirm|remove ...")
}

switch command {
case "enroll":
    guard arguments.count == 3 else { die("usage: ecv-auth enroll <account> <reason>") }
    authenticate(reason: arguments[2])
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
        die("could not generate random bytes")
    }
    let secret = Data(bytes)
    storeSecret(account: arguments[1], secret: secret)
    print(secret.base64EncodedString())
case "unlock":
    guard arguments.count == 3 else { die("usage: ecv-auth unlock <account> <reason>") }
    authenticate(reason: arguments[2])
    print(loadSecret(account: arguments[1]).base64EncodedString())
case "confirm":
    guard arguments.count == 2 else { die("usage: ecv-auth confirm <reason>") }
    authenticate(reason: arguments[1])
case "remove":
    guard arguments.count == 2 else { die("usage: ecv-auth remove <account>") }
    SecItemDelete(baseQuery(account: arguments[1]) as CFDictionary)
default:
    die("unknown command '\(command)'")
}
