package org.uom.idp.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonObject;
import org.uom.idp.exceptions.DecodeLicenseKeyException;
import org.uom.idp.exceptions.PublicKeyException;
import org.uom.idp.exceptions.VerifyLicenseKeyException;
import org.uom.idp.utils.Constants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

import static org.uom.idp.utils.Constants.*;

/**
 * This class validates the license key.
 * <p>
 * This class holds the "premain" method of the Java agent. This method reads the license
 * key file located at {Carbon Home}/{@link Constants#LICENSE_KEY_PATH} and validate against,
 * 1. Issuer
 * 2. Expire date
 * 3. {@link Constants#API_CODES_CLAIM}
 * 4. Signature
 *
 * @since 1.0.0
 */
public class LicenseValidator {

    private static final Logger logger = Logger.getLogger(LicenseValidator.class.getName());

    /**
     * After the Java Virtual Machine (JVM) has initialized,  premain method will be called. This method will load
     * the license key and validate followings,
     * <p>
     * 1. Issuer
     * 2. Expire date
     * 3. {@link Constants#API_CODES_CLAIM}
     * 4. Signature
     *
     * @param agentArgument Argument passed for the Java agent
     */
    public JsonObject premain(final String agentArgument) throws VerifyLicenseKeyException, DecodeLicenseKeyException, PublicKeyException {
        DecodedJWT decodedJWT = decodeLicenseKey(agentArgument);
        verifyLicenseKey(decodedJWT);
        return createOutput("true");
    }

    /**
     * This method create the output Object
     *
     * @param jwt       JWT token
     * @return JsonObject
     */
    private JsonObject createOutput(String jwt) {

        JsonObject output = new JsonObject();
        output.addProperty("success", jwt);
        return output;
    }



    /**
     * Returns an Input stream for the Public cert file in the resources/{@link Constants#PUBLIC_KEY}.
     *
     * @return {@link InputStream}
     */
    private static InputStream getPublicKeyFileStream() {
        return LicenseValidator.class.getClassLoader().getResourceAsStream(PUBLIC_KEY);

    }

    /**
     * Load public certificate in .pem format as a {@link RSAPublicKey}.
     *
     * @return public key {@link RSAPublicKey}
     * @throws PublicKeyException If cannot construct the public certificate
     */
    private static RSAPublicKey getRSAPublicKey() throws PublicKeyException {
        byte[] fileContent;
        try (InputStream inputStream = getPublicKeyFileStream();
             ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, len);
            }
            byteArrayOutputStream.flush();
            fileContent = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            String errMsg = String.format("Couldn't load the public key file: %s", PUBLIC_KEY);
            throw new PublicKeyException(errMsg, e);
        }
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(fileContent);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(ALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new PublicKeyException(String.format("Couldn't find the algorithm %s", ALGORITHM_RSA), e);
        }
        RSAPublicKey publicKey;
        try {
            publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        } catch (InvalidKeySpecException e) {
            throw new PublicKeyException("Invalid public key", e);
        }
        return publicKey;
    }

    /**
     * This method reads the license key from the given file and construct a JWT if the following claims are
     * present,
     * 1. Issuer
     * 2. Expire date
     * 3. {@link Constants#API_CODES_CLAIM}
     * @param licenseKey license key
     * @return Decoded JWT token {@link DecodedJWT}
     * @throws DecodeLicenseKeyException If the JWT is not valid
     */
    private static DecodedJWT decodeLicenseKey(String licenseKey) throws DecodeLicenseKeyException {
        
        DecodedJWT decodedJWT = JWT.decode(licenseKey);
        if (decodedJWT.getIssuer() == null) {
            throw new DecodeLicenseKeyException("Issuer claim is not defined");
        }
        if (decodedJWT.getExpiresAt() == null) {
            throw new DecodeLicenseKeyException("Expire data is not defined");
        }
        String[] jwtProductCodes = decodedJWT.getClaim(API_CODES_CLAIM).asArray(String.class);
        if (jwtProductCodes == null || jwtProductCodes.length == 0) {
            throw new DecodeLicenseKeyException(String.format("%s claim is not configured or empty",
                    API_CODES_CLAIM));
        }
        return decodedJWT;
    }
    /**
     * Verifies following JWT claims.
     * <p>
     * 1. Signature
     * 2. Expire date
     * 3. The Product code claim is valid if the product code or "wso2carbon" is with in
     * the jwt claim {@link Constants#API_CODES_CLAIM}.
     * 4. Issuer
     * <p>
     * Assumption: Decoded JWT has {@link Constants#API_CODES_CLAIM} & "exp" claims
     *
     * @param decodedJWT Decode JWT
     * @throws PublicKeyException        If cannot construct the public certificate
     * @throws VerifyLicenseKeyException If the token is invalid
     */
    private static void verifyLicenseKey(final DecodedJWT decodedJWT)
            throws PublicKeyException, VerifyLicenseKeyException {

        Algorithm algorithm = Algorithm.RSA256(getRSAPublicKey(), null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(Constants.ISSUER)
                .build();
        // Verify Expire date + signature
        try {
            verifier.verify(decodedJWT);
        } catch (TokenExpiredException e) {
            throw new VerifyLicenseKeyException("License key has expired", e);
        } catch (InvalidClaimException e) {
            throw new VerifyLicenseKeyException("Issuer is invalid", e);
        } catch (JWTVerificationException e) {
            throw new VerifyLicenseKeyException("Signature is invalid", e);
        }
    }

}
