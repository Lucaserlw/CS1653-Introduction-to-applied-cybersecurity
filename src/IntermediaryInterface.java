// For when UI needs to ask question but client needs the answer
// Don't want UI to handle values directly in the middle of protocols

interface IntermediaryInterface {
    String askPassword();
    boolean checkFingerprint(String server, String fingerprint);
}