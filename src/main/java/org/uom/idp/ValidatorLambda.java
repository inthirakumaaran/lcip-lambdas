package org.uom.idp;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.uom.idp.exceptions.DecodeLicenseKeyException;
import org.uom.idp.exceptions.PublicKeyException;
import org.uom.idp.exceptions.VerifyLicenseKeyException;
import org.uom.idp.model.TokenData;
import org.uom.idp.service.LicenseValidator;

/**
 * Hello world!
 *
 */
public class ValidatorLambda implements RequestHandler<TokenData, Object>
{
    private LicenseValidator licenseValidator;

    public static void main(String[] args) {
        LicenseValidator licenseValidator1 = new LicenseValidator();

        JsonObject response = null;
        try {
            response = licenseValidator1.premain("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJhcGlDb2RlcyI6WyJhcGkxIiwiYXBpMiJdLCJpc3MiOiJ1b20ubGsiLCJleHAiOjE2MzY1NjkwMDAsImlhdCI6MTYxMzkyMzY4NX0.riVIFkCdAQmGFd8ldoDY_jap7-kDIWjvivIGknruzU4hi7aARgQPNtdoOWQdMbeI70UEHVpmXxHSgee0zx6I_E1OaoVsdxCtBToRjRTdtNulM4zggV5yIqZ-WVvC6OLgLzHohNlrKeVp7Y7W9A18aukAzxv13rO3O5fvA5-CPWzscf-n3pvGo9o4idbw2yyYxJhnCWwlb_VNmcRIg6UAIjcm2P4TspHiCVI0IxZb6fpT8Lm8VNdMCZtjnwQFWVsRfOlQPpwpQNPhQHB1kDnK11ooPPiLJbGJOIu5vYUHvu2XUYeh9z-wi0ktjC6k5ruIgYT1CKwAEfDAklGx86iosQ");
        } catch (VerifyLicenseKeyException e) {
            e.printStackTrace();
        } catch (DecodeLicenseKeyException e) {
            e.printStackTrace();
        } catch (PublicKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(response.toString());
    }

    @Override
    public Object handleRequest(TokenData token, Context context) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println("Invoking Validator Lambda function");
        System.out.println("Printing token : " + token.getToken());

        if (licenseValidator == null) {
            licenseValidator = new LicenseValidator();
        }

        JsonObject response = null;
        try {
            response = licenseValidator.premain(token.getToken());
        } catch (VerifyLicenseKeyException e) {
            e.printStackTrace();
        } catch (DecodeLicenseKeyException e) {
            e.printStackTrace();
        } catch (PublicKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return response == null ? "Exception thrown" : response.toString();
    }
}
