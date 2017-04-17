package com.theironyard.api;

import org.json.JSONObject;
import org.json.XML;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class AmazonUtil {

    private static String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
    private static String AWS_SECRET_KEY = System.getenv("AWS_SECRET_KEY");
    private static final String ENDPOINT = "ecs.amazonaws.com";

    public static String lookUpItem(String keywords, String searchCategory, String page) {

        SignedRequestsHelper helper;

        try {
            helper = SignedRequestsHelper.getInstance(ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_KEY);
        } catch (Exception e) {
            e.printStackTrace();
            return "Problem with the request helper";
        }

        //Load search parameters
        Map<String, String> params = new HashMap<>();
        params.put("Service", "AWSECommerceService");
        params.put("Version", "2009-03-31");
        params.put("SearchIndex", searchCategory);
        params.put("Operation", "ItemSearch");
        params.put("ItemPage", page);
        params.put("ResponseGroup", "ItemAttributes, Images");
        params.put("Keywords", keywords); //Keyword(s) entered by user
        params.put("AssociateTag", "safe0cd-20");


        try {
            URL url = new URL(helper.sign(params));

            BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
            String strTemp;
            while (null != (strTemp = br.readLine())) {
                JSONObject xmlJSONObj = XML.toJSONObject(strTemp);
                String jsonFormattedString = xmlJSONObj.toString(0);

                return jsonFormattedString;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            return "Please verify search parameters";
        }

        return "Please verify the status of the Product API";
    }
}
