package com.example.twitterchallenge;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.tomcat.util.json.JSONParser;
import org.json.simple.JSONObject;

import java.util.stream.LongStream;


import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.auth.AccessToken;
import twitter4j.conf.ConfigurationBuilder;


@RestController
public class GreetingController{
    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();
    private String oauthConsumerKey,oauthNonce,oauthSignatureMethod,oauthTimestamp,oauthToken,
            oauthVersion,status,includeEntities,oauthSignature, consumerSecret,oauthTokenSecret,URL, requestType;
    private String   bearerToken="AAAAAAAAAAAAAAAAAAAAAD81%2FAAAAAAA83niJ4OpzbXWt0PvSfsXvr5HZEQ%3DkMbTQ2yrJ8EfL0DyGWxu6UI6vLiwhcm9AilRLcyVglGt3o95vs";

    // This method initialises all the variables necessary  to create the authorization header
    // In a real world application these keys would have to be either hidden or encrypted.
    public void Init(){
        /*
        String APIKey="h6Ep9i2MgqL9Uu8ysFNZWDohY";
        String APISecretKey="zCHT7SwW2Msceg6gIxDyTLa9Mjc7Lmm8oDMHjBvkFXbUjU9dHa ";
        String AccessToken="289238395-r9OQq8rb8LUQQ65Kn1p29CQKS3Uxae1LLfgDUSFB";
        String SecretAccessToken="XX9fLUxkZCVY9m5iRPkEmn9kChMkrpVK3suXBW6kF3BPL";

         */
        this.URL="https://api.twitter.com/1.1/lists/subscribers.json?list_id=1130185227375038465&skip_status=true";
        this.oauthConsumerKey="h6Ep9i2MgqL9Uu8ysFNZWDohY";
        this.oauthSignatureMethod="HMAC-SHA1";
        this.oauthNonce=createNonce();
        this.oauthSignature="tnnArxj06cWHq44gCs1OSKk/jLY=";
        this.oauthTimestamp=createTimestamp();
        this.oauthToken="289238395-r9OQq8rb8LUQQ65Kn1p29CQKS3Uxae1LLfgDUSFB";
        this.oauthVersion="1.0";
        this.consumerSecret="zCHT7SwW2Msceg6gIxDyTLa9Mjc7Lmm8oDMHjBvkFXbUjU9dHa";
        this.oauthTokenSecret="XX9fLUxkZCVY9m5iRPkEmn9kChMkrpVK3suXBW6kF3BPL";
        this.requestType="POST";
        Authorization authorization = new Authorization(oauthConsumerKey,oauthToken,consumerSecret,oauthTokenSecret,URL,
                oauthNonce,oauthSignatureMethod,oauthTimestamp,requestType );

        this.oauthSignature=authorization.generateSignature();
    }

    // Maps  any request with a /followers parameter to this method. Because the request is a GET request
    // we can use the bearer token  which was generated seperately by a curl request.
    //This method takes in the username  from the request  then returns the list of followers for that username.
    @RequestMapping("followers")
    public Object  response(@RequestParam("name") String username){
        Init();
        try {
            String auth="";
            BigInteger cursor= BigInteger.valueOf(-1);  // cursor is used to paginate results.


            URL="https://api.twitter.com/1.1/followers/list.json?cursor=-1&screen_name="+ username +"&skip_status=true&include_user_entities=false&count=200";
            auth="Bearer "+bearerToken;
            HashMap arr= new HashMap();
            ArrayList users= new ArrayList();

            // Loops through all the pages of followers for a user and combines the result into a list.
            // I was unable to fully test the system because the standard twitter api only allows 15 requests/15 min for a given API endpoint.
            do {
                CloseableHttpClient client = HttpClients.createDefault();
                HttpGet httpGet= (HttpGet)createRequest("bearer",auth);
                HttpResponse response=client.execute(httpGet);
                String JSonResponse= new BasicResponseHandler().handleResponse(response);
                JSONParser parse= new JSONParser(JSonResponse);
                HashMap arr2= (HashMap)parse.parse();
                String key = "next_cursor";
                cursor=(BigInteger) arr2.get(key);
                ArrayList usr=(ArrayList) arr2.get("users");
                for ( int i=0;i<usr.size();i++){
                    users.add(usr.get(i));
                }
                URL="https://api.twitter.com/1.1/followers/list.json?cursor="+String.valueOf(cursor)+"&screen_name="+ username +"&skip_status=true&include_user_entities=false&count=200";
                //1636222277028128767
                // cursor!=BigInteger.valueOf(10000)

            }while(users.size()<1000&&cursor!=BigInteger.valueOf(0));
            return  users;
        }catch (Exception e){
            e.printStackTrace();
            return new JSONObject();
        }

    }

    // Maps  any request with a /tweets  parameter to this method. Because the request is a GET request
    // we can use the bearer token  which was generated seperately by a curl request.
    //This method takes in the username  from the request  then returns the list of tweets  for that username.
    @RequestMapping("tweets")
    public Object getTweets(@RequestParam("name") String username){
        try{
            String auth="";
            BigInteger cursor= BigInteger.valueOf(200);


            URL="https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name="+username+"&count="+cursor;
            auth="Bearer "+bearerToken;
            HashMap arr= new HashMap();
            ArrayList tweets= new ArrayList();

            // This for loop functions similarly to the the get followers loop
            do{
                CloseableHttpClient client = HttpClients.createDefault();
                HttpGet httpGet=(HttpGet) createRequest("bearer",auth);
                HttpResponse response=client.execute(httpGet);
                String JSonResponse= new BasicResponseHandler().handleResponse(response);
                JSONParser parse= new JSONParser(JSonResponse);
                ArrayList map=(ArrayList) parse.parse();
                return map;
            }while(tweets.size()<1000&cursor!=BigInteger.valueOf(0));


        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return "Something went wrong " ;
    }
    // This method returns a HTTPGEt object with the correct headers for the /tweets and /followers requests
    private  Object createRequest(String type,String auth){

        if (type=="bearer"){
            HttpGet httpGet= new HttpGet(URL);
            httpGet.addHeader("Host","api.twitter.com");
            httpGet.addHeader("User-Agent","Mini twitter coding challenge");
            httpGet.addHeader("Authorization",auth);
            httpGet.addHeader("Accept-Encoding","gzip");
            return httpGet;
        }
        else{
            return false;
        }
    }

    // Second attempt at trying to get the authorization for POST requests working using the twitter4j library.
    public String follow4j(String pUsername){
        String response="";
        try{
            ConfigurationBuilder cb = new ConfigurationBuilder();
            cb.setDebugEnabled(true)
                    .setOAuthConsumerKey(oauthConsumerKey)
                    .setOAuthConsumerSecret(consumerSecret)
                    .setOAuthAccessToken(oauthToken)
                    .setOAuthAccessTokenSecret(oauthTokenSecret);
            TwitterFactory tf = new TwitterFactory();

            Twitter twitter = tf.getInstance();
            twitter.setOAuthConsumer(oauthConsumerKey,consumerSecret);
            AccessToken token= new AccessToken(oauthToken,oauthTokenSecret);
            twitter.setOAuthAccessToken(token);
            response =twitter.createFriendship(pUsername).toString();
            System.out.println(response);
        } catch (TwitterException e) {
            e.printStackTrace();
        }

        return response;
    }


    @RequestMapping("follow")
    public Object follow(@RequestParam("name") String username){

        Init();
        follow4j("twitterdev");



        try{

            // First atttempt at generating the correct POST request with a valid authorization header
            /*
            String auth="";
            CloseableHttpClient client = HttpClients.createDefault();
            URL="https://api.twitter.com/1.1/friendships/create.json?user_id=2244994945&follow=true";
            auth=createHeader();
            HttpPost httpPost=new HttpPost(URL);
            httpPost.addHeader("Authorization",auth);
            httpPost.addHeader("content-type","application/json");
            Header[] headers=httpPost.getAllHeaders();

            HttpResponse response=client.execute(httpPost);
            String JSonResponse= new BasicResponseHandler().handleResponse(response);
            JSONParser parse= new JSONParser(JSonResponse);
            Object arr= parse.parse();

            return   arr;
                       */
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return "hell"  ;
    }
    // This method combines all the variables needed to produce a valid authorization fiels in the header for a POST request.
    public String createHeader(){
        String Auth ="";
        Authorization authorization = new Authorization();
        Auth+="OAuth ";
        Auth+=authorization.percentEncode("oauth_consumer_key")+"="+"\""+authorization.percentEncode(oauthConsumerKey)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_nonce")+"="+"\""+authorization.percentEncode(oauthNonce)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_signature")+"="+"\""+authorization.percentEncode(oauthSignature)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_signature_method")+"="+"\""+authorization.percentEncode(oauthSignatureMethod)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_timestamp")+"="+"\""+authorization.percentEncode(oauthTimestamp)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_token")+"="+"\""+authorization.percentEncode(oauthToken)+"\""+", ";
        Auth+=authorization.percentEncode("oauth_version")+"="+"\""+authorization.percentEncode(oauthVersion)+"\"";
        return Auth;

    }
    // Attempt at generating the 32 byte random data.
    public String createNonce(){


        Random rand= new Random();
        LongStream x=rand.longs(32);
        String nonce=x.toString();
        nonce= Base64.getEncoder().encodeToString(nonce.getBytes());
        nonce=nonce.replaceAll("[^\\p{L}\\p{Nd}]+", "");
        nonce=nonce.substring(0,32);
        try {
            int lenght= nonce.getBytes("UTF-8").length;
            System.out.println(lenght);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return nonce;
    }
    // Method returns the time elapse since the UNIX epoch
    public String createTimestamp(){

        Long time = Instant.now().getEpochSecond();
        String timeString= time.toString();
        return timeString;
    }





}
