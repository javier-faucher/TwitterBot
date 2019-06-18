package com.example.twitterchallenge;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Hex;

public class Authorization {

    public Authorization(String pConsKey,String pOauthToken, String pConsSecret, String pOauthTokenSecret,
                         String URL,String pNonce,String pSignMethod, String pTimeStamp, String pRequestType){
        this.oauthConsumerKey=pConsKey;
        this.oauthToken=pOauthToken;
        this.consumerSecret=pConsSecret;
        this.oauthTokenSecret=pOauthTokenSecret;
        this.oauthNonce=pNonce;
        this.oauthSignatureMethod=pSignMethod;
        this.oauthTimestamp=pTimeStamp;
        this.URL=URL;
        this.requestType=pRequestType;
/*
        this.oauthConsumerKey="xvz1evFS4wEEPTGEFPHBog";
        this.oauthToken="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
        this.consumerSecret="kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
        this.oauthTokenSecret="LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
        this.oauthNonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
        this.oauthSignatureMethod="HMAC-SHA1";
        this.oauthTimestamp="1318622958";
        this.URL="https://api.twitter.com/1.1/statuses/update.json";
        this.requestType="POST";
        */

    }
    public Authorization(){

    }
    private String oauthConsumerKey,oauthNonce,oauthSignatureMethod,oauthTimestamp,oauthToken,
            oauthVersion,status,includeEntities,oauthSignature, consumerSecret,oauthTokenSecret,URL,requestType;

    // This method takes in all the parameters for the given request sorts them in alphabetical order and then
    // combines them into a single string and returns the string.
    public String creatParamString (){

        Map<String, String > dict= new HashMap<String ,String >();
        //dict.put("status","Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%2520OAuth%2520request%2521");
        // dict.put("status","Hello Ladies + Gentlemen, a signed OAuth request!");
        dict.put("follow","true");
        dict.put ("user_id", "2244994945");
        dict.put("oauth_consumer_key",oauthConsumerKey);
        dict.put("oauth_nonce",oauthNonce);
        dict.put("oauth_signature_method",oauthSignatureMethod);
        dict.put("oauth_timestamp",oauthTimestamp);
        dict.put("oauth_token",oauthToken);
        dict.put("oauth_version","1.0");
        Map <String, String>dict2=new HashMap<String,String>();
        // dict2=dict;
        String firstStep="";
        for ( Map.Entry<String,String> entry: dict.entrySet()){
            dict2.put(entry.getKey(), percentEncode(entry.getValue()));

        }
        do{

            String check = "z";
            for ( Map.Entry<String,String> entry: dict2.entrySet()){
                String key = entry.getKey();
                String value=entry.getValue();
                if ( key.compareTo(check)<1){
                    System.out.println(key);
                    check= key;
                }
            }
            firstStep+=check;
            firstStep+="=";
            firstStep+=dict2.get(check);
            if (dict2.size()>1){
                firstStep+="&";
            }
            dict2.remove(check);
            System.out.println(firstStep);

        }while(dict2.size()>0);
        return firstStep;

    }


    // This method calls the methods necessary to generates the signature and returns the signature
    // this method is the one that will be call whenever a signature is necesarry.
    public String generateSignature(){
        String paramString= creatParamString();
        String baseString=createBaseSignString(requestType,URL,paramString);
        String signingKey=getSigningKey(consumerSecret,oauthTokenSecret);
        String signature= createSignature(baseString,signingKey);
        System.out.println(baseString);
        return signature;

    }
    //This method combines the request method, the request URL and the previously generated Parameter string to
    // produce the Base signature string  which will be combined with the signing key to produce the signature.
    public String createBaseSignString(String p_Method,String p_URL ,String p_ParamString){

        String base="";
        p_Method=p_Method.toUpperCase();
        base+=p_Method;
        base+="&";
        p_URL= percentEncode(p_URL);
        base+=p_URL;
        base+="&";
        base+= percentEncode(p_ParamString);
        System.out.println(base);
        return base;

    }
    // This method generates the signing key by combining the consumer secret and the token secret
    public String  getSigningKey(String p_ConsumerSecret, String p_tokenSecret){
        String signingKey="";
        p_ConsumerSecret= percentEncode(p_ConsumerSecret);
        p_tokenSecret= percentEncode(p_tokenSecret);
        signingKey+=p_ConsumerSecret;
        signingKey+="&";
        signingKey+=p_tokenSecret;
        return signingKey;

    }

    // This method generates the HMAC-SHA signature given the base string and the signing key
    public  String createSignature(String p_Base,String p_Key){
        byte[] hexed= new byte[0];
        String signature="";
        try {
            byte[] key_Bytes = p_Key.getBytes();
            SecretKeySpec key = new SecretKeySpec(key_Bytes, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(key);
            byte [] raw =mac.doFinal(p_Base.getBytes());
            signature = Base64.getEncoder().encodeToString(raw);

            hexed=  new Hex().encode(raw);
            String BinaryString= new String(hexed,"UTF-8");
            BinaryString = BinaryString.toUpperCase();
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return  signature;

    }


    //This method takes in a string and returns the percent Encoded version of that string
    public String percentEncode(String pUnecoded) {
        //if null, keep null (no gain or loss of safety)
        if (pUnecoded == null)
            return null;

        StringBuilder builder = new StringBuilder();
        for (char character : pUnecoded.toCharArray())
            switch (character) {
                case '#':
                    builder.append("%23");
                    continue;
                case '!':
                    builder.append("%21");
                    continue;
                case '?':
                    builder.append("%3F");
                    continue;
                case '$':
                    builder.append("%24");
                    continue;
                case '&':
                    builder.append("%26");
                    continue;
                case '\'':
                    builder.append("%27");
                    continue;
                case '(':
                    builder.append("%28");
                    continue;
                case ')':
                    builder.append("%29");
                    continue;
                case '*':
                    builder.append("%2A");
                    continue;
                case '+':
                    builder.append("%2B");
                    continue;
                case ',':
                    builder.append("%2C");
                    continue;
                case '/':
                    builder.append("%2F");
                    continue;
                case ':':
                    builder.append("%3A");
                    continue;
                case ';':
                    builder.append("%3B");
                    continue;
                case '=':
                    builder.append("%3D");
                    continue;

                case '@':
                    builder.append("%40");
                    continue;
                case '[':
                    builder.append("%5B");
                    continue;
                case ']':
                    builder.append("%5D");
                    continue;
                case ' ':
                    builder.append("%20");
                    continue;
                case '"':
                    builder.append("%22");
                    continue;
                case '%':
                    builder.append("%25");
                    continue;

                case '<':
                    builder.append("%3C");
                    continue;
                case '>':
                    builder.append("%3E");
                    continue;
                case '\\':
                    builder.append("%5C");
                    continue;
                case '^':
                    builder.append("%5E");
                    continue;

                case '`':
                    builder.append("%60");
                    continue;
                case '{':
                    builder.append("%7B");
                    continue;
                case '|':
                    builder.append("%7C");
                    continue;
                case '}':
                    builder.append("%7D");
                    continue;

                default:
                    builder.append(character);//if it does not need to be escaped, add the character itself to the StringBuilder
            }
        return builder.toString();//build the string, and return
    }
}
