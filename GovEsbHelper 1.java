package com.zax.testing.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Slf4j
@Component
public class GovEsbHelper {

    @Value("${govesb.client-private-key}")
    public String clientPrivateKey;

    @Value("${govesb.public-key}")
    public String esbPublicKey;

    @Value("${govesb.client-id}")
    public String clientId;

    @Value("${govesb.client-secret}")
    public String clientSecret;

    @Value("${govesb.token-url}")
    public String esbTokenUrl;

    @Value("${govesb.engine-url}")
    public String esbEngineUrl;

    @Value("${govesb.nida-user-id}")
    public String nidaUserId;
    public String apiCode;
    public String requestBody;

    public String format = "json";
    public String accessToken;

    /*public GovEsbHelper(){
        this.format = "json";
        this.clientId = "";
        this.clientSecret = "";
        this.clientPrivateKey = "";
        this.esbPublicKey = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEon0az66Kz+6ZIz4G7La8uPeSbOT/E/suRjNMgFQ4isjJwFXaS20vHcndEFxXz8M68sbxkbLrGuNS/wFcEzubWQ==";
        this.esbTokenUrl = "https://esbdemo.gov.go.tz/gw/govesb-uaa/oauth/token";
        this.esbEngineUrl = "https://esbdemo.gov.go.tz/engine/esb";
        this.nidaUserId = "";
    }*/

    public JsonNode getAccessToken() throws Exception {
        JsonNode tokenResponse;
        String responseString;
        String plainCredentials = clientId + ":" + clientSecret;
        String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
        String authorizationHeader = "Basic " + base64Credentials;
        try {
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost request = new HttpPost(this.esbTokenUrl);
            List<NameValuePair> nvps = new ArrayList<>();
            nvps.add(new BasicNameValuePair("client_id", clientId));
            nvps.add(new BasicNameValuePair("client_secret", clientSecret));
            nvps.add(new BasicNameValuePair("grant_type", "client_credentials"));
            request.setEntity(new UrlEncodedFormEntity(nvps));
            request.addHeader("Authorization", authorizationHeader);
            request.addHeader("Content-Type", "application/x-www-form-urlencoded");
            HttpResponse response = httpClient.execute(request);
            responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
            ObjectMapper mapper = new ObjectMapper();
            tokenResponse = mapper.readTree(responseString);
            if (response.getStatusLine().getStatusCode() == 200) {
                if (tokenResponse.has("access_token")) {
                    this.accessToken = tokenResponse.get("access_token").asText();
                }
            } else {
                throw new Exception("Could not get access token from esb");
            }
            System.out.println("Token response: " + tokenResponse);
            return tokenResponse;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    //Normal Synchronous requests
    public String requestData(String apiCode, String requestBody, String format) throws Exception {
        return request(apiCode, requestBody, format, false, null, this.esbEngineUrl + "/request", null);
    }

    //Nida requests
    public String requestNida(String apiCode, String requestBody, String format) throws Exception {
        if (this.nidaUserId == null) {
            throw new Exception("nidaUserId is required");
        }
        return request(apiCode, requestBody, format, false, this.nidaUserId, this.esbEngineUrl + "/nida-request", null);
    }


    //Pushing data to GovESB
    public String pushData(String apiCode, String requestBody, String format) throws Exception {
        return request(apiCode, requestBody, format, true, null, this.esbEngineUrl + "/push-request", null);
    }

    private String request(String apiCode, String requestBody, String format, boolean isPushRequest, String nidaUserId, String esbRequestUrl, HashMap<String, String> headers) throws Exception {
        initializeRequest(apiCode, requestBody, format);
        String esbRequestBody = createEsbRequest(isPushRequest, nidaUserId);
        System.out.println("Request to GovESB: " + esbRequestBody);
        String esbResponse = sendEsbRequest(esbRequestBody, esbRequestUrl, headers);
        log.info("GovESB Response: {}", esbResponse);
        return this.verifyThenReturnData(esbResponse, this.format);
    }

    public String successResponse(String requestBody, String format) throws Exception {
        return esbResponse(true, requestBody, null, format, false);
    }

    public String failureResponse(String requestBody, String message, String format) throws Exception {
        return esbResponse(false, requestBody, message, format, false);
    }

    //Return a handled successful asynchronous response
    public String handledFailureResponse(String requestBody, String message, String format)  {
        try {
			return esbResponse(false, requestBody, message, format, false);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
    } 
    
    //Return a successful asynchronous response
    public String asyncSuccessResponse(String requestBody, String format) throws Exception {
        return esbResponse(true, requestBody, null, format, true);
    }

    //Return a failure asynchronous response
    public String asyncFailureResponse(String requestBody, String message, String format) throws Exception {
        return esbResponse(false, requestBody, message, format, true);
    }

    private String esbResponse(boolean isSuccess, String requestBody, String message, String format, boolean isAsyncResponse) throws Exception {
        return createEsbResponse(isSuccess, requestBody, message, isAsyncResponse);
    }

    private String createEsbResponse(boolean isSuccess, String requestBody, String message, boolean isAsyncResponse) throws Exception {
        if (this.format.equals("json")) {
            return createJsonResponse(isSuccess, requestBody, message, isAsyncResponse);
        } else {
            return createXmlResponse(isSuccess, requestBody, message, isAsyncResponse);
        }
    }


    private String createJsonResponse(boolean isSuccess, String requestBody, String message, boolean isAsyncResponse) throws Exception {
        ObjectMapper mapper = new JsonMapper();
        JsonNode dataNode = createResponseData(isSuccess, requestBody, message, isAsyncResponse);
        String signature = this.signData(dataNode.toString());
        ObjectNode responseNode = mapper.createObjectNode();
        responseNode.set("data", dataNode);
        responseNode.put("signature", signature);
        return responseNode.toString();
    }

    private String createXmlResponse(boolean isSuccess, String requestBody, String message, boolean isAsyncResponse) throws Exception {
        ObjectMapper mapper = new XmlMapper();
        JsonNode dataNode = this.createResponseData(isSuccess, requestBody, message, isAsyncResponse);
        String dataString = mapper.writer().withRootName("data").writeValueAsString(dataNode);
        String signature = this.signData(dataString);
        ObjectNode responseNode = mapper.createObjectNode();
        responseNode.set("data", dataNode);
        responseNode.put("signature", signature);
        return mapper.writer().withRootName("esbresponse").writeValueAsString(responseNode);
    }

    private ObjectNode createResponseData(boolean isSuccess, String requestBody, String message, boolean isAsyncResponse) throws JsonProcessingException {
        ObjectMapper mapper = getMapper();
        ObjectNode dataNode = mapper.createObjectNode();
        dataNode.put("success", isSuccess);

        if (requestBody != null) {
            JsonNode esbBodyNode = mapper.readTree(requestBody);
            dataNode.set("esbBody", esbBodyNode);
        }
        if (message != null && !isSuccess) {
            dataNode.put("message", message);
        }

        if (isAsyncResponse && isSuccess) {
            dataNode.put("requestId", this.apiCode);
        }

        return dataNode;
    }

    //todo make sure format and other required properties are not null

    public String verifyThenReturnData(String esbResponse, String format) throws JsonProcessingException {
        if (format != null) {
            this.format = format;
        }

        ObjectMapper mapper = this.getMapper();
        JsonNode node;
        node = mapper.readTree(esbResponse);

        String data = "";
        String signature = node.get("signature").asText();
        if (this.format.equals("json")) {
            data = node.get("data").toString();
        } else {
            data = mapper.writer().withRootName("data").writeValueAsString(node.get("data"));
        }
        boolean isValid = verifyPayloadECC(data, signature);
        if (!isValid) {
            System.out.println("Signature verification failed!");
            return null;
        }
        return data;
    }

    private ObjectMapper getMapper() {
        return this.format.equals("json") ? new JsonMapper() : new XmlMapper();
    }

    private void initializeRequest(String apiCode, String requestBody, String format) throws Exception {
        assertNotNull();
        this.getAccessToken();
        this.validateRequestParameters(apiCode, requestBody, format);
    }

    private String sendEsbRequest(String requestBody, String esbRequestUrl, HashMap<String, String> headers) {
        String esbResponse = "";

        try {
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost request = new HttpPost(esbRequestUrl);
            request.addHeader("Authorization", "Bearer " + this.accessToken);
            request.addHeader("Content-Type", "application/" + this.format + "; charset=utf-8" );

            if (headers != null && !headers.isEmpty()) {
                for (Map.Entry<String, String> header :
                        headers.entrySet()) {
                    request.addHeader(header.getKey(), header.getValue());
                }
            }

            StringEntity requestEntity = new StringEntity(requestBody, "UTF-8");
            request.setEntity(requestEntity);
            HttpResponse response = httpClient.execute(request);
            esbResponse = EntityUtils.toString(response.getEntity(), "UTF-8");
            System.out.println("Response from GovESB: " + esbResponse);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return esbResponse;
    }

    private String createEsbRequest(boolean isPushRequest, String userId) throws Exception {
        if (this.format.equals("json")) {
            return this.createJsonRequest(isPushRequest, userId);
        } else if (this.format.equals("xml")) {
            return this.createXmlRequest(isPushRequest, userId);
        }
        return null;
    }

    private String createJsonRequest(boolean isPushRequest, String userId) throws Exception {
        ObjectNode esbRequestNode = this.createEsbData(isPushRequest, userId);
        String payload = esbRequestNode.toString();
        String signature = this.signData(payload);
        ObjectNode node = new JsonMapper().createObjectNode();
        node.set("data", esbRequestNode);
        node.put("signature", signature);
        return node.toString();
    }

    private String createXmlRequest(boolean isPushRequest, String userId) throws Exception {
        this.requestBody = "<root>" + this.requestBody + "</root>";
        ObjectNode esbRequestNode = this.createEsbData(isPushRequest, userId);
        XmlMapper mapper = new XmlMapper();
        String payload = mapper.writer().withRootName("data").writeValueAsString(esbRequestNode);
        String signature = this.signData(payload);
        ObjectNode node = new XmlMapper().createObjectNode();
        node.set("data", esbRequestNode);
        node.put("signature", signature);
        return mapper.writer().withRootName("esbrequest").writeValueAsString(node);
    }

    private ObjectNode createEsbData(boolean isPushRequest, String userId) throws JsonProcessingException {
        ObjectMapper mapper = this.format.equals("json") ? new JsonMapper() : new XmlMapper();
        ObjectNode esbRequestNode = mapper.createObjectNode();
        esbRequestNode.put(isPushRequest ? "pushCode" : "apiCode", this.apiCode);

        if (userId != null) {
            esbRequestNode.put("userId", this.nidaUserId);
            ObjectNode payloadNode = mapper.createObjectNode();
            payloadNode.set("Payload", mapper.readTree(this.requestBody));
            esbRequestNode.set("esbBody", payloadNode);
        } else {
            if (this.requestBody != null) {
                esbRequestNode.put("esbBody", mapper.readTree(this.requestBody));
            }
        }
        return esbRequestNode;
    }

    private String signData(String payload) throws Exception {
        return signPayloadECC(payload);
    }

    private String signPayloadECC(String payload) throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(this.clientPrivateKey.replace("\n", "")));
            PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(payload.getBytes(StandardCharsets.UTF_8));
            byte[] signature = ecdsaSign.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    private boolean verifyPayloadECC(String data, String signature) {
        try {
            Signature ecdsaVerifySignature = Signature.getInstance("SHA256withECDSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(this.esbPublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            ecdsaVerifySignature.initVerify(publicKey);
            ecdsaVerifySignature.update(data.getBytes(StandardCharsets.UTF_8));
            return ecdsaVerifySignature.verify(Base64.getMimeDecoder().decode(signature));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void validateRequestParameters(String apiCode, String requestBody, String format) throws Exception {
        if (apiCode != null && !apiCode.isEmpty()) {
            this.apiCode = apiCode;
        }

        if (requestBody != null && !requestBody.isEmpty()) {
            this.requestBody = requestBody;
        }

        if (format != null && !format.isEmpty()) {
            this.format = format;
        }

        if (this.apiCode == null) {
            throw new Exception("apiCode can not be null");
        }

        if (this.format == null || (!this.format.equalsIgnoreCase("json") && !this.format.equalsIgnoreCase("xml"))) {
            throw new Exception("format can not be null");
        }
    }

    private void assertNotNull() throws Exception {
        if (this.clientId == null || this.clientSecret == null || this.clientPrivateKey == null ||
                this.esbPublicKey == null || this.esbTokenUrl == null || this.esbEngineUrl == null) {
            throw new Exception("Some EsbHelper properties are null: make sure all required EsbHelper properties are set");
        }
    }

    public void setClientPrivateKey(String clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public void setEsbPublicKey(String esbPublicKey) {
        this.esbPublicKey = esbPublicKey;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setEsbTokenUrl(String esbTokenUrl) {
        this.esbTokenUrl = esbTokenUrl;
    }

    public void setEsbEngineUrl(String esbEngineUrl) {
        this.esbEngineUrl = esbEngineUrl;
    }

    public void setNidaUserId(String nidaUserId) {
        this.nidaUserId = nidaUserId;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getFormat() {
        return format;
    }

	public String getEsbData(String dataBody, String format, String field) throws JsonProcessingException {
		if (format != null) {
			this.format = format;
		}

		ObjectMapper mapper = this.getMapper();
		JsonNode node;
		node = mapper.readTree(dataBody);

		String data = "";
		if (this.format.equals("json")) {
			if(node.get(field) != null) {
				data = node.get(field).toString();
			}
			
		} else {
			data = mapper.writer().withRootName(field).writeValueAsString(node.get(field));
		}

		return data;
	}

    /*
     * ENCRYPTION AND DECRYPTION FUNCTIONS
     * */

    private static final String HKDF_INFO = "aes-encryption";
    private static final int AES_KEY_LENGTH = 32; // 256 bits
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final String KEY_EXCHANGE = "ECDH";
    private static final String ENCRYPTION_SCHEME = "AES/GCM/NoPadding";
    private static final String BC_PROVIDER = "BC";
    private static final String EC_SCHEME = "EC";
    private static final String AES_ALG = "AES";
    private static final String DECRYPTION_SCHEME = "AES/GCM/NoPadding";

    public String encrypt(String data, String recipientPublicKeyPem) throws Exception {

        recipientPublicKeyPem = getPublicKey(recipientPublicKeyPem);

        // 1. Generate ephemeral ECC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_SCHEME, BC_PROVIDER);

        String curveName = getPublicKeyCurveName(recipientPublicKeyPem);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        keyPairGenerator.initialize(spec);
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKey ephemeralPrivateKey = (ECPrivateKey) ephemeralKeyPair.getPrivate();
        ECPublicKey ephemeralPublicKey = (ECPublicKey) ephemeralKeyPair.getPublic();

        // 2. Parse recipient's public key
        ECPublicKey recipientPublicKey = parsePemPublicKeyEncrypt(recipientPublicKeyPem);

        // 3. Derive shared secret using ECDH
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_EXCHANGE, BC_PROVIDER);
        keyAgreement.init(ephemeralPrivateKey);
        keyAgreement.doPhase(recipientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 4. Derive AES key using HKDF
        byte[] aesKeyBytes = hkdf(sharedSecret, HKDF_INFO.getBytes(), AES_KEY_LENGTH);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, AES_ALG);

        // 5. Generate IV and encrypt data with AES-GCM
        byte[] iv = new byte[GCM_IV_LENGTH];

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_SCHEME, BC_PROVIDER);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(data.getBytes());


        // Split ciphertext and tag (GCM returns ciphertext + tag)
        byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - GCM_TAG_LENGTH, ciphertext.length);
        byte[] encryptedData = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - GCM_TAG_LENGTH);

        // 6. Convert ephemeral public key to PEM format
        String ephemeralPublicKeyPem = convertToPem(ephemeralPublicKey);

        // 7. Package the data (PHP expects tag FIRST, then ciphertext)
        byte[] encryptedDataWithTag = ByteBuffer.allocate(tag.length + encryptedData.length).put(tag).put(encryptedData)
                .array();

        // 8. Return as JSON
        JSONObject jsonObj = new JSONObject();
        jsonObj.putOnce("ephemeralKey", Base64.getEncoder().encodeToString(ephemeralPublicKeyPem.getBytes()));
        jsonObj.putOnce("iv", Base64.getEncoder().encodeToString(iv));
        jsonObj.putOnce("encryptedData", Base64.getEncoder().encodeToString(encryptedDataWithTag));
        return jsonObj.toString();
    }

    public String decrypt(String encryptedDataJson) throws Exception {

        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = this.getPrivateFromPem(getPrivateKey(this.clientPrivateKey));

        // Parse JSON (use a proper JSON parser like Jackson in production)
        String ephemeralKeyPem = extractFromJson(encryptedDataJson, "ephemeralKey");
        String ivBase64 = extractFromJson(encryptedDataJson, "iv");
        String encryptedDataBase64 = extractFromJson(encryptedDataJson, "encryptedData");

        // Decode Base64 components
        byte[] iv = java.util.Base64.getDecoder().decode(ivBase64);
        byte[] encryptedDataWithTag = org.bouncycastle.util.encoders.Base64.decode(encryptedDataBase64);

        // Split tag (first 16 bytes) and ciphertext
        byte[] tag = Arrays.copyOfRange(encryptedDataWithTag, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(encryptedDataWithTag, 16, encryptedDataWithTag.length);

        // 1. Parse the PEM-formatted ephemeral public key
        ECPublicKey ephemeralPublicKey = parsePemPublicKeyDecrypt(ephemeralKeyPem);

        // 2. Derive shared secret using ECDH
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_EXCHANGE, BC_PROVIDER);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(ephemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 3. Derive AES key using HKDF
        byte[] aesKeyBytes = hkdf(sharedSecret, HKDF_INFO.getBytes(), AES_KEY_LENGTH);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, AES_ALG);

        // 4. Decrypt with AES-GCM
        Cipher cipher = Cipher.getInstance(DECRYPTION_SCHEME, BC_PROVIDER);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH*8, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);

        // Combine ciphertext + tag for decryption
        byte[] plaintext = cipher.doFinal(ByteBuffer.allocate(ciphertext.length + tag.length)
                .put(ciphertext)
                .put(tag)
                .array());

        return new String(plaintext);
    }

    private String extractFromJson(String json, String key) {
        // Simple regex-based JSON parsing (use a proper JSON parser in production)
        String pattern = "\"" + key + "\":\"([^\"]+)\"";
        java.util.regex.Pattern r = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = r.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        throw new IllegalArgumentException("Key " + key + " not found in JSON");
    }

    private static ECPublicKey parsePemPublicKeyEncrypt(String pem) throws Exception {

        PEMParser pemParser = new PEMParser(new StringReader(pem));
        SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
        ECPublicKey ogKey = (ECPublicKey) new JcaPEMKeyConverter().setProvider(BC_PROVIDER).getPublicKey(publicKeyInfo);

        return ogKey;
    }

    private ECPublicKey parsePemPublicKeyDecrypt(String pem) throws Exception {
        PEMParser pemParser = new PEMParser(new StringReader(new String(Base64.getDecoder().decode(pem.getBytes()))));
        SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
        return (ECPublicKey) converter.getPublicKey(publicKeyInfo);
    }

    private static String convertToPem(ECPublicKey publicKey) throws Exception {
        // This is a simplified PEM conversion - in production use BouncyCastle's
        // PEMWriter
        byte[] encoded = publicKey.getEncoded();
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(encoded) + "\n" + "-----END PUBLIC KEY-----";
    }

    private static byte[] hkdf(byte[] ikm, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, null, info));
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }

    public org.bouncycastle.jce.interfaces.ECPrivateKey getPrivateFromPem(String pemString) throws IOException {
        PEMParser pemParser = new PEMParser(new StringReader(pemString));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParser.readObject();
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
        return privateKey;
    }

    public String getPublicKeyCurveName(String pemKey) throws Exception {
        String publicKeyPEM = pemKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) publicKey;
            ECParameterSpec params = ecKey.getParameters();

            if (params instanceof ECNamedCurveParameterSpec) {
                return ((ECNamedCurveParameterSpec) params).getName();
            } else {
                // Fallback for unnamed curves
                return "Unnamed curve (field size: " + params.getCurve().getFieldSize() + ")";
            }
        }

        return "Not an EC key";
    }

    private String getPublicKey(String publicKeyString) {
        return "-----BEGIN PUBLIC KEY-----\n" + publicKeyString +"\n" + "-----END PUBLIC KEY-----";
    }

    private String getPrivateKey(String privateKeyString) {
        return "-----BEGIN PRIVATE KEY-----\n" + privateKeyString +"\n" + "-----END PRIVATE KEY-----";
    }
}
