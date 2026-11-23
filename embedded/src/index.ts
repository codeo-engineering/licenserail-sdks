// licenserail-embedded: the LicenseRail client core for apps that run inside a host platform (YouTrack apps, browser
// extensions, web apps, workers). No dependencies and no Node APIs; needs ES2020 (BigInt).

export { utf8Encode, utf8Decode, base64Decode, hex } from './encoding.js'
export { sha256 } from './sha256.js'
export { verifyP256, parsePublicKey } from './p256.js'
export { verifyToken, verifyTokenAsync, decodeTokenUnverified, type Fingerprint, type LicensePayload } from './token.js'
export { hashComponent, installationFingerprint, fingerprintMatches, isHostInstallation, HOST_PLATFORMS, UNAVAILABLE, type ComponentPart } from './fingerprint.js'
export { evaluate, summarize, hasFeature, type LicenseStatus, type LicenseSummary } from './evaluate.js'
export {
  activateRequest, refreshRequest, deactivateRequest, trialRequest, readResponse, refreshDueAt, REVOKING_CODES, INSTALLATION_HEADER,
  type HttpRequestDescription, type ActivateOptions, type RefreshOptions, type TrialOptions, type ClientResponse, type Target,
} from './protocol.js'
export { createLicenseClient, type ClientOptions, type LicenseStorage, type Transport, type LicenseState, type ActionResult, type LicenseClient } from './client.js'
