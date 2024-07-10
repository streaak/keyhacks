<p align="center">
  <img src="https://user-images.githubusercontent.com/18099289/56750563-558a9400-6784-11e9-8175-ee2a19ee9d75.png" width="300px">
</p>
</br>

KeyHacks shows methods to validate different API keys found on a Bug Bounty Program or a pentest.

@Gwen001 has scripted the entire process available here and it can be found [here](https://github.com/gwen001/pentest-tools/blob/master/keyhacks.sh)

# Table of Contents

- [ABTasty API Key](#ABTasty-API-Key)
- [Algolia API key](#Algolia-API-key)
- [Amplitude API Keys](#Amplitude-API-Keys)
- [Asana Access token](#Asana-Access-Token)
- [AWS Access Key ID and Secret](#AWS-Access-Key-ID-and-Secret)
- [Azure Application Insights APP ID and API Key](#Azure-Application-Insights-APP-ID-and-API-Key)
- [Bazaarvoice Passkey](#Bazaarvoice-Passkey)
- [Bing Maps API Key](#Bing-Maps-API-Key)
- [Bit.ly Access token](#Bitly-Access-token)
- [Branch.io Key and Secret](#BranchIO-Key-and-Secret)
- [BrowserStack Access Key](#BrowserStack-Access-Key)
- [Buildkite Access token](#Buildkite-Access-token)
- [ButterCMS API Key](#ButterCMS-API-Key)
- [Calendly API Key](#Calendly-API-Key)
- [Contentful Access Token](#Contentful-access-token)
- [CircleCI Access Token](#CircleCI-Access-Token)
- [Cloudflare API key](#cloudflare-api-key)
- [Cypress record key](#Cypress-record-key)
- [DataDog API key](#DataDog-API-key)
- [Delighted API key](#Delighted-api-key)
- [Deviant Art Access Token](#Deviant-Art-Access-Token)
- [Deviant Art Secret](#Deviant-Art-Secret)
- [Dropbox API](#Dropbox-API)
- [Facebook Access Token](#Facebook-Access-Token)
- [Facebook AppSecret](#Facebook-AppSecret)
- [Firebase](#Firebase)
- [Firebase Cloud Messaging (FCM)](#Firebase-Cloud-Messaging)
- [FreshDesk API Key](#FreshDesk-API-key)
- [Github client id and client secret](#Github-client-id-and-client-secret)
- [GitHub private SSH key](#GitHub-private-SSH-key)
- [Github Token](#Github-Token)
- [Gitlab personal access token](#Gitlab-personal-access-token)
- [GitLab runner registration token](#Gitlab-runner-registration-token)
- [Google Cloud Service Account credentials](#Google-Cloud-Service-Account-credentials)
- [Google Maps API key](#Google-Maps-API-key)
- [Google Recaptcha key](#Google-Recaptcha-key)
- [Grafana Access Token](#Grafana-Access-Token)
- [Help Scout OAUTH](#Help-Scout-OAUTH)
- [Heroku API key](#Heroku-API-key)
- [HubSpot API key](#Hubspot-API-key)
- [Infura API key](#Infura-API-key)
- [Instagram Access Token](#Instagram-Access-Token)
- [Instagram Basic Display API](#Instagram-Basic-Display-API-Access-Token)
- [Instagram Graph API](#Instagram-Graph-Api-Access-Token)
- [Ipstack API Key](#Ipstack-API-Key)
- [Iterable API Key](#Iterable-API-Key)
- [JumpCloud API Key](#JumpCloud-API-Key)
- [Keen.io API Key](#Keenio-API-Key)
- [LinkedIn OAUTH](#LinkedIn-OAUTH)
- [Lokalise API Key](#Lokalise-API-Key)
- [Loqate API Key](#Loqate-API-key)
- [MailChimp API Key](#MailChimp-API-Key)
- [MailGun Private Key](#MailGun-Private-Key)
- [Mapbox API key](#Mapbox-API-Key)
- [Microsoft Azure Tenant](#Microsoft-Azure-Tenant)
- [Microsoft Shared Access Signatures (SAS)](#Microsoft-Shared-Access-Signatures-(SAS))
- [Microsoft Teams Webhook](#Microsoft-Teams-Webhook)
- [New Relic Personal API Key (NerdGraph)](#New-Relic-Personal-API-Key-(NerdGraph))
- [New Relic REST API](#New-Relic-REST-API)
- [NPM token](#NPM-token)
- [OpsGenie API Key](#OpsGenie-API-Key)
- [Pagerduty API token](#Pagerduty-API-token)
- [Paypal client id and secret key](#Paypal-client-id-and-secret-key)
- [Pendo Integration Key](#Pendo-Integration-Key)
- [PivotalTracker API Token](#PivotalTracker-API-Token)
- [Razorpay API key and secret key](#Razorpay-keys)
- [Salesforce API key](#Salesforce-API-key)
- [SauceLabs Username and access Key](#SauceLabs-Username-and-access-Key)
- [SendGrid API Token](#SendGrid-API-Token)
- [Shodan.io](#Shodan-Api-Key)
- [Slack API token](#Slack-API-token)
- [Slack Webhook](#Slack-Webhook)
- [Sonarcloud](#Sonarcloud-Token)
- [Spotify Access Token](#Spotify-Access-Token)
- [Square](#Square)
- [Stripe Live Token](#Stripe-Live-Token)
- [Telegram Bot API Token](#Telegram-Bot-API-Token)
- [Travis CI API token](#Travis-CI-API-token)
- [Twilio Account_sid and Auth token](#Twilio-Account_sid-and-Auth-token)
- [Twitter API Secret](#Twitter-API-Secret)
- [Twitter Bearer token](#Twitter-Bearer-token)
- [Visual Studio App Center API Token](#Visual-Studio-App-Center-API-Token)
- [WakaTime API Key](#WakaTime-API-Key)
- [WeGlot Api Key](#weglot-api-key)
- [WPEngine API Key](#WPEngine-API-Key)
- [YouTube API Key](#YouTube-API-Key)
- [Zapier Webhook Token](#Zapier-Webhook-Token)
- [Zendesk Access token](#Zendesk-Access-Token)
- [Zendesk API key](#Zendesk-api-key)


# Detailed Information

## [Slack Webhook](https://api.slack.com/incoming-webhooks)

If the below command returns `missing_text_or_fallback_or_attachments`, it means that the URL is valid, any other responses would mean that the URL is invalid.
```
curl -s -X POST -H "Content-type: application/json" -d '{"text":""}' "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

## [Slack API token](https://api.slack.com/web)
```
curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1"
```

or

```
curl -sX POST "https://slack.com/api/auth.test" -H "Accept: application/json; charset=utf-8" -H "Authorization: Bearer xoxb-TOKEN_HERE"
```

## [SauceLabs Username and access Key](https://wiki.saucelabs.com/display/DOCS/Account+Methods)
```
curl -u USERNAME:ACCESS_KEY https://saucelabs.com/rest/v1/users/USERNAME
```

## Facebook AppSecret

You can generate access tokens by visiting the URL below.

```
https://graph.facebook.com/oauth/access_token?client_id=ID_HERE&client_secret=SECRET_HERE&redirect_uri=&grant_type=client_credentials
```

## Facebook Access Token  
```
https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2
```

## [Firebase](https://firebase.google.com/)
Requires a **custom token**, and an **API key**.

1. Obtain ID token and refresh token from custom token and API key: `curl -s -XPOST -H 'content-type: application/json' -d '{"token":":custom_token","returnSecureToken":True}' 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=:api_key'`
2. Exchange ID token for auth token: `curl -s -XPOST -H 'content-type: application/json' -d '{"idToken":":id_token"}' https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=:api_key'`

## [Github Token](https://developer.github.com/v3/)
```
curl -s -u "user:apikey" https://api.github.com/user
curl -s -H "Authorization: token TOKEN_HERE" "https://api.github.com/users/USERNAME_HERE/orgs"
# Check scope of your api token
curl "https://api.github.com/rate_limit" -i -u "user:apikey" | grep "X-OAuth-Scopes:"
```

## [Github client id and client secret](https://developer.github.com/v3/#oauth2-keysecret)
```
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'
```

## [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging)

Reference: https://abss.me/posts/fcm-takeover

```
curl -s -X POST --header "Authorization: key=AI..." --header "Content-Type:application/json" 'https://fcm.googleapis.com/fcm/send' -d '{"registration_ids":["1"]}'
```

## GitHub private SSH key

SSH private keys can be tested against github.com to see if they are registered against an existing user account. If the key exists the username corresponding to the key will be provided. ([source](https://github.com/streaak/keyhacks/issues/2))

```
$ ssh -i <path to SSH private key> -T git@github.com
Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.
```

## [Twilio Account_sid and Auth token](https://www.twilio.com/docs/iam/api/account)
```
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts.json' -u ACCOUNT_SID:AUTH_TOKEN
```

## [Twitter API Secret](https://developer.twitter.com/en/docs/basics/authentication/guides/bearer-tokens.html)
```
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

## [Twitter Bearer token](https://developer.twitter.com/en/docs/accounts-and-users/subscribe-account-activity/api-reference/aaa-premium)
```
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
```

## [HubSpot API key](https://developers.hubspot.com/docs/methods/owners/get_owners)

Get all owners:
```
https://api.hubapi.com/owners/v2/owners?hapikey={keyhere}
```
Get all contact details:
```
https://api.hubapi.com/contacts/v1/lists/all/contacts/all?hapikey={keyhere}

```

## [Infura API key](https://docs.infura.io/infura/networks/ethereum/how-to/secure-a-project/project-id)
```
curl https://mainnet.infura.io/v3/<YOUR-API-KEY> -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}'
```

## [Deviant Art Secret](https://www.deviantart.com/developers/authentication)
```
curl https://www.deviantart.com/oauth2/token -d grant_type=client_credentials -d client_id=ID_HERE -d client_secret=mysecret
```

## [Deviant Art Access Token](https://www.deviantart.com/developers/authentication)
```
curl https://www.deviantart.com/api/v1/oauth2/placebo -d access_token=Alph4num3r1ct0k3nv4lu3
```

## [Pendo Integration Key](https://help.pendo.io/resources/support-library/api/index.html?bash#authentication)
```
curl -X GET https://app.pendo.io/api/v1/feature -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'
curl -X GET https://app.pendo.io/api/v1/metadata/schema/account -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'
```

## [SendGrid API Token](https://docs.sendgrid.com/api-reference)
```
curl -X "GET" "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer SENDGRID_TOKEN-HERE" -H "Content-Type: application/json"
```

## [Square](https://squareup.com/)
**Detection:**

App id/client secret:  `sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`
Auth token: `EAAA[a-zA-Z0-9]{60}`

**Test App id & client secret:**
```
curl "https://squareup.com/oauth2/revoke" -d '{"access_token":"[RANDOM_STRING]","client_id":"[APP_ID]"}'  -H "Content-Type: application/json" -H "Authorization: Client [CLIENT_SECRET]"
```

Response indicating valid credentials:
```
empty
```

Response indicating invalid credentials:
```
{
  "message": "Not Authorized",
  "type": "service.not_authorized"
}
```

**Test Auth token:**
```
curl https://connect.squareup.com/v2/locations -H "Authorization: Bearer [AUHT_TOKEN]"
```

Response indicating valid credentials:
```
{"locations":[{"id":"CBASELqoYPXr7RtT-9BRMlxGpfcgAQ","name":"Coffee \u0026 Toffee SF","address":{"address_line_1":"1455 Market Street","locality":"San Francisco","administrative_district_level_1":"CA","postal_code":"94103","country":"US"},"timezone":"America/Los_Angeles"........
```

Response indicating invalid credentials:
```
{"errors":[{"category":"AUTHENTICATION_ERROR","code":"UNAUTHORIZED","detail":"This request could not be authorized."}]}
```
## [Contentful Access Token](https://www.contentful.com/developers/docs/references/authentication)
```
curl -v https://cdn.contentful.com/spaces/SPACE_ID_HERE/entries\?access_token\=ACCESS_TOKEN_HERE
```

## [Dropbox API](https://www.dropbox.com/developers/documentation/http/documentation)
```
curl -X POST https://api.dropboxapi.com/2/users/get_current_account --header "Authorization: Bearer TOKEN_HERE"
```

## [AWS Access Key ID and Secret](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html)

Install [awscli](https://aws.amazon.com/cli/), set the [access key and secret to environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html), and execute the following command:
```
AWS_ACCESS_KEY_ID=xxxx AWS_SECRET_ACCESS_KEY=yyyy aws sts get-caller-identity
```

AWS credentials' permissions can be determined using [Enumerate-IAM](https://github.com/andresriancho/enumerate-iam).
This gives broader view of the discovered AWS credentials privileges instead of just checking S3 buckets.

```
git clone https://github.com/andresriancho/enumerate-iam
cd  enumerate-iam
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

## [Lokalise API Key](https://app.lokalise.com/api2docs/curl/#resource-authentication)
```curl --request GET \
  --url https://api.lokalise.com/api2/projects/ \
  --header 'x-api-token: [API-KEY-HERE]'
```

## [MailGun Private Key](https://documentation.mailgun.com/en/latest/api_reference.html)
```
curl --user 'api:YOUR_API_KEY' "https://api.mailgun.net/v3/domains"
```

## [FreshDesk API Key](https://developers.freshdesk.com/api/#getting-started)
```
curl -v -u user@yourcompany.com:test -X GET 'https://domain.freshdesk.com/api/v2/groups/1'
This requires the API key in 'user@yourcompany.com', pass in 'test' and 'domain.freshdesk.com' to be the instance url of the target. In case you get a 403, try the endpoint api/v2/tickets, which is accessible for all keys.

```
## [JumpCloud API Key](https://docs.jumpcloud.com/1.0/authentication-and-authorization/authentication-and-authorization-overview)

#### [v1](https://docs.jumpcloud.com/1.0/systemusers)
```
List systems:
curl -H "x-api-key: APIKEYHERE" "https://console.jumpcloud.com/api/systems"
curl -H "x-api-key: APIKEYHERE" "https://console.jumpcloud.com/api/systemusers"
curl -H "x-api-key: APIKEYHERE" "https://console.jumpcloud.com/api/applications"
```

#### [v2](https://docs.jumpcloud.com/2.0/systems/list-the-associations-of-a-system)

```
List systems:
curl -X GET https://console.jumpcloud.com/api/v2/systems/{System_ID}/memberof \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: {API_KEY}'
```

## Microsoft Azure Tenant
Format:
```
CLIENT_ID: [0-9a-z\-]{36}
CLIENT_SECRET: [0-9A-Za-z\+\=]{40,50}
TENANT_ID: [0-9a-z\-]{36}
```
Verification:
```
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'client_id=<CLIENT_ID>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=<CLIENT_SECRET>&grant_type=client_credentials' 'https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token'
```

## [Microsoft Shared Access Signatures (SAS)](https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/storage/common/storage-dotnet-shared-access-signature-part-1.md)

The following powershell can be used to test a Shared Access Signature Token:
```powershell
static void UseAccountSAS(string sasToken)
{
    // Create new storage credentials using the SAS token.
    StorageCredentials accountSAS = new StorageCredentials(sasToken);
    // Use these credentials and the account name to create a Blob service client.
    CloudStorageAccount accountWithSAS = new CloudStorageAccount(accountSAS, "account-name", endpointSuffix: null, useHttps: true);
    CloudBlobClient blobClientWithSAS = accountWithSAS.CreateCloudBlobClient();

    // Now set the service properties for the Blob client created with the SAS.
    blobClientWithSAS.SetServiceProperties(new ServiceProperties()
    {
        HourMetrics = new MetricsProperties()
        {
            MetricsLevel = MetricsLevel.ServiceAndApi,
            RetentionDays = 7,
            Version = "1.0"
        },
        MinuteMetrics = new MetricsProperties()
        {
            MetricsLevel = MetricsLevel.ServiceAndApi,
            RetentionDays = 7,
            Version = "1.0"
        },
        Logging = new LoggingProperties()
        {
            LoggingOperations = LoggingOperations.All,
            RetentionDays = 14,
            Version = "1.0"
        }
    });

    // The permissions granted by the account SAS also permit you to retrieve service properties.
    ServiceProperties serviceProperties = blobClientWithSAS.GetServiceProperties();
    Console.WriteLine(serviceProperties.HourMetrics.MetricsLevel);
    Console.WriteLine(serviceProperties.HourMetrics.RetentionDays);
    Console.WriteLine(serviceProperties.HourMetrics.Version);
}
```

## [Microsoft Teams Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using)
If the below command returns `Summary or Text is required.`, it means that the URL is valid. If it returns `Invalid webhook URL` or any other responses would mean that the URL is invalid.
```
curl -H "Content-Type:application/json" -d "{'text':''}" "YOUR_WEBHOOK_URL"
```

## [New Relic Personal API Key (NerdGraph)](https://docs.newrelic.com/docs/apis/nerdgraph/get-started/introduction-new-relic-nerdgraph#endpoint)

```
curl -X POST https://api.newrelic.com/graphql \
-H 'Content-Type: application/json' \
-H 'API-Key: YOUR_API_KEY' \
-d '{ "query":  "{ requestContext { userId apiKey } }" } '
```

## [New Relic REST API](https://docs.newrelic.com/docs/apis/rest-api-v2/application-examples-v2/list-your-app-id-metric-timeslice-data-v2)

```
curl -X GET 'https://api.newrelic.com/v2/applications.json' \
     -H "X-Api-Key:${APIKEY}" -i
```

If valid, test further to see if it's an [admin key](https://docs.newrelic.com/docs/apis/get-started/intro-apis/types-new-relic-api-keys#admin)

## [Heroku API key](https://devcenter.heroku.com/articles/platform-api-quickstart)
```
curl -X POST https://api.heroku.com/apps -H "Accept: application/vnd.heroku+json; version=3" -H "Authorization: Bearer API_KEY_HERE"
```
## [Mapbox API key](https://docs.mapbox.com/api/)

Mapbox secret keys start with `sk`, rest start with `pk` (public token), `sk` (secret token), or `tk` (temporary token).

```
curl "https://api.mapbox.com/geocoding/v5/mapbox.places/Los%20Angeles.json?access_token=ACCESS_TOKEN"

#Check token validity
curl "https://api.mapbox.com/tokens/v2?access_token=YOUR_MAPBOX_ACCESS_TOKEN"

#Get list of all tokens associated with an account. (only works if the token is a Secret Token (sk), and has the appropiate scope)
curl "https://api.mapbox.com/tokens/v2/MAPBOX_USERNAME_HERE?access_token=YOUR_MAPBOX_ACCESS_TOKEN"
```

## [Salesforce API key](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/quickstart_oauth.htm)
```
curl https://instance_name.salesforce.com/services/data/v20.0/ -H 'Authorization: Bearer access_token_here'
```

## [Algolia API key](https://www.algolia.com/doc/rest-api/search/#overview)

If the key has the `listIndexes` permission, you can list indexes with:
```
curl --request GET \
  --url https://<example-app-id>-1.algolianet.com/1/indexes/ \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-appid>'
```

Otherwise you will have to know the name of an index (check the app source code or the requests it does). Then to enumerate its content:
```
curl --request GET \
  --url https://<example-app-id>-1.algolianet.com/1/indexes/<example-index> \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-appid>'
```

Be cautious when running this command, since the payload might execute within an administrative environment, depending on what index you are editing the `highlightPreTag` of. It's recommended to use a more silent payload (such as XSS Hunter) to prove the possible cross-site scripting attack.

```
curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'
```

## [Zapier Webhook Token](https://zapier.com/help/how-get-started-webhooks-zapier/)
```
curl -H "Accept: application/json" -H "Content-Type: application/json" -X POST -d '{"name":"streaak"}' "webhook_url_here"
```

## [Pagerduty API token](https://support.pagerduty.com/docs/using-the-api)
```
curl -H "Accept: application/vnd.pagerduty+json;version=2"  -H "Authorization: Token token=TOKEN_HERE" -X GET  "https://api.pagerduty.com/schedules"
```

## [BrowserStack Access Key](https://www.browserstack.com/automate/rest-api)
```
curl -u "USERNAME:ACCESS_KEY" https://api.browserstack.com/automate/plan.json
```

## [Google Maps API key](https://developers.google.com/maps/documentation/javascript/get-api-key)

**Key restrictions are set per service. When testing the key, if the key is restricted/inactive on one service try it with another.**

| Name| Endpoint| Pricing|
| ------------- |:-------------:| -----:|
| Static Maps     | https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE| $2 |
| Streetview     | https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=KEY_HERE| $7 |
| Embed | https://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key=KEY_HERE| Varies |
| Directions | https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=KEY_HERE| $5 |
| Geocoding | https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=KEY_HERE| $5 |
| Distance Matrix| https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=KEY_HERE | $5 |
|Find Place from Text | https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HERE | Varies |
| Autocomplete | https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=KEY_HERE| Varies |
| Elevation | https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=KEY_HERE | $5 |
| Timezone | https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=KEY_HERE | $5 |
| Roads | https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795\|60.170879,24.942796\|60.170877,24.942796&key=KEY_HERE | $10|
| Geolocate | https://www.googleapis.com/geolocation/v1/geolocate?key=KEY_HERE| $5 |

*\*Pricing is in USD per 1000 requests (for the first 100k requests)*

More Information available here-

https://medium.com/@ozguralp/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e

https://github.com/ozguralp/gmapsapiscanner/

https://developers.google.com/maps/api-key-best-practices

## [Google Recaptcha key](https://developers.google.com/recaptcha/docs/verify)

Send a POST to the following URL:

```
https://www.google.com/recaptcha/api/siteverify
```

`secret` and `response` are two required POST parameters, where `secret` is the key and `response` is the response to test for.

Regular expression: `^6[0-9a-zA-Z_-]{39}$`. The API key always starts with a 6 and is 40 chars long. Read more here: https://developers.google.com/recaptcha/docs/verify.

## [Google Cloud Service Account credentials](https://cloud.google.com/docs/authentication/production)

Service Account credentials may be found in a JSON file like this:

```
$ cat service_account.json
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n",
  "client_email": "...",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}
```

If this is your case you may check these credentials using `gcloud` tool ([how to install `gcloud`](https://cloud.google.com/sdk/docs/quickstart-debian-ubuntu)):

```
$ gcloud auth activate-service-account --key-file=service_account.json
Activated service account credentials for: [...]
$ gcloud auth print-access-token
ya29.c...
```

In case of success you'll see access token printed in terminal. Please note that after verifying that credentials are actually valid you may want to enumerate permissions of these credentials which is another story.

## [Branch.IO Key and Secret](https://docs.branch.io/pages/apps/deep-linking-api/#app-read)

Visit the following URL to check for validity:

```
https://api2.branch.io/v1/app/KEY_HERE?branch_secret=SECRET_HERE
```

## [Bing Maps API Key](https://docs.microsoft.com/en-us/bingmaps/rest-services/locations/find-a-location-by-address)

Visit this link to check for the key's validity. A valid key's response should start with `authenticationResultCode:	"ValidCredentials"`

```
https://dev.virtualearth.net/REST/v1/Locations?CountryRegion=US&adminDistrict=WA&locality=Somewhere&postalCode=98001&addressLine=100%20Main%20St.&key=API_KEY
```

## [Bit.ly Access token](https://dev.bitly.com/authentication.html)

Visit the following URL to check for validity:

```
https://api-ssl.bitly.com/v3/shorten?access_token=ACCESS_TOKEN&longUrl=https://www.google.com
```

## [Buildkite Access token](https://buildkite.com/docs/apis/rest-api)
```
curl -H "Authorization: Bearer ACCESS_TOKEN" \
https://api.buildkite.com/v2/access-token
```

## [ButterCMS-API-Key](https://buttercms.com/docs/api/#authentication)
```
curl -X GET 'https://api.buttercms.com/v2/posts/?auth_token=your_api_token'
```

## [Asana Access token](https://asana.com/developers/documentation/getting-started/auth#personal-access-token)
```
curl -H "Authorization: Bearer ACCESS_TOKEN" https://app.asana.com/api/1.0/users/me
```

## [Zendesk Access token](https://support.zendesk.com/hc/en-us/articles/203663836-Using-OAuth-authentication-with-your-application)
```
curl https://{subdomain}.zendesk.com/api/v2/tickets.json \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## [Zendesk Api Key](https://developer.zendesk.com/api-reference/ticketing/introduction/)
API tokens are different from OAuth tokens, API tokens are auto-generated passwords in the Support admin interface.
```
curl https://{target}.zendesk.com/api/v2/users.json \  -u support@{target}.com/token:{here your token}
```

## [MailChimp API Key](https://developer.mailchimp.com/documentation/mailchimp/reference/overview/)
```
curl --request GET --url 'https://<dc>.api.mailchimp.com/3.0/' --user 'anystring:<API_KEY>' --include
```

## [WPEngine API Key](https://wpengineapi.com/)

This issue can be further exploited by checking out [@hateshape](https://github.com/hateshape/)'s gist https://gist.github.com/hateshape/2e671ea71d7c243fac7ebf51fb738f0a.

```
curl "https://api.wpengine.com/1.2/?method=site&account_name=ACCOUNT_NAME&wpe_apikey=WPENGINE_APIKEY"
```

## [DataDog API key](https://docs.datadoghq.com/api/)
```
curl "https://api.datadoghq.com/api/v1/dashboard?api_key=<api_key>&application_key=<application_key>"
```

## [Delighted API key](https://app.delighted.com/docs/api)
Do not delete the `:` at the end.
```
curl https://api.delighted.com/v1/metrics.json \
  -H "Content-Type: application/json" \
  -u YOUR_DELIGHTED_API_KEY:
```

## [Travis CI API token](https://developer.travis-ci.com/gettingstarted)

```
curl -H "Travis-API-Version: 3" -H "Authorization: token <TOKEN>" https://api.travis-ci.org/repos
```

## [Telegram Bot API Token](https://core.telegram.org/bots/api#making-requests)

```
curl https://api.telegram.org/bot<TOKEN>/getMe
```

## [WakaTime API Key](https://wakatime.com/developers)
```
curl "https://wakatime.com/api/v1/users/current?api_key=KEY_HERE"
```

## [Sonarcloud Token](https://sonarcloud.io/web_api)
```
curl -u <token>: "https://sonarcloud.io/api/authentication/validate"
```

## [Spotify Access Token](https://developer.spotify.com/documentation/general/guides/authorization-guide/)
```
curl -H "Authorization: Bearer <ACCESS_TOKEN>" https://api.spotify.com/v1/me
```

## [Instagram Basic Display API Access Token](https://developers.facebook.com/docs/instagram-basic-display-api/getting-started)
E.g.: IGQVJ...
```
curl -X GET 'https://graph.instagram.com/{user-id}?fields=id,username&access_token={access-token}'
```

## [Instagram Graph API Access Token](https://developers.facebook.com/docs/instagram-api/getting-started)
E.g.: EAAJjmJ...
```
curl -i -X GET 'https://graph.facebook.com/v8.0/me/accounts?access_token={access-token}'
```

## [Gitlab personal access token](https://docs.gitlab.com/ee/api/README.html#personal-access-tokens)
```
curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"
```

## [GitLab runner registration token](https://docs.gitlab.com/runner/register/)
```
docker run --rm gitlab/gitlab-runner register \
  --non-interactive \
  --executor "docker" \
  --docker-image alpine:latest \
  --url "https://gitlab.com/" \
  --registration-token "PROJECT_REGISTRATION_TOKEN" \
  --description "keyhacks-test" \
  --maintenance-note "Testing token with keyhacks" \
  --tag-list "docker,aws" \
  --run-untagged="true" \
  --locked="false" \
  --access-level="not_protected"
```

## [Paypal client id and secret key](https://developer.paypal.com/docs/api/get-an-access-token-curl/)
```
curl -v https://api.sandbox.paypal.com/v1/oauth2/token \
   -H "Accept: application/json" \
   -H "Accept-Language: en_US" \
   -u "client_id:secret" \
   -d "grant_type=client_credentials"
```

The access token can be further used to extract data from the PayPal API. More information: https://developer.paypal.com/docs/api/overview/#make-rest-api-calls.

This can be verified using:

```
curl -v -X GET "https://api.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1" -H "Content-Type: application/json" -H "Authorization: Bearer [ACCESS_TOKEN]"
```

## [Stripe Live Token](https://stripe.com/docs/api/authentication)

```
curl https://api.stripe.com/v1/charges -u token_here:
```

Keep the colon at the end of the token to prevent `cURL` from requesting a password.

The token is always in the following format: `sk_live_24charshere`, where the `24charshere` part contains 24 characters from `a-z A-Z 0-9`. There is also a test key, which starts with `sk_test`, but this key is worthless since it is only used for testing purposes and most likely doesn't contain any sensitive information. The live key, on the other hand, can be used to extract/retrieve a lot of info — ranging from charges to the complete product list.

Keep in mind that you will never be able to get the full credit card information since Stripe only gives you the last 4 digits.

More info/complete documentation: https://stripe.com/docs/api/authentication.

## [Razorpay API key and Secret key](https://razorpay.com/docs/api/)

This can be verified using:

```
curl -u <YOUR_KEY_ID>:<YOUR_KEY_SECRET> \
  https://api.razorpay.com/v1/payments
```

## [CircleCI Access Token](https://circleci.com/docs/api/#api-overview)

```
curl https://circleci.com/api/v1.1/me?circle-token=<TOKEN>
```

## [Cloudflare API key](https://api.cloudflare.com/#user-api-tokens-verify-token)

```
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer <YOUR_API_TOKEN>"
```

## [Loqate API key](https://www.loqate.com/resources/support/apis)

```
curl 'http://api.addressy.com/Capture/Interactive/Find/v1.00/json3.ws?Key=<KEY_HERE>&Countries=US,CA&Language=en&Limit=5&Text=BHAR'
```

## [Ipstack API Key](https://ipstack.com/documentation)

```
curl 'https://api.ipstack.com/{ip_address}?access_key={keyhere}'
```

## [NPM token](https://docs.npmjs.com/about-authentication-tokens)

You can verify NPM token [using `npm`](https://medium.com/bugbountywriteup/one-token-to-leak-them-all-the-story-of-a-8000-npm-token-79b13af182a3) (replacing `00000000-0000-0000-0000-000000000000` with NPM token):

```
export NPM_TOKEN="00000000-0000-0000-0000-000000000000"
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
npm whoami
```

Another way to verify token is to query API directly:

```
curl -H 'authorization: Bearer 00000000-0000-0000-0000-000000000000' 'https://registry.npmjs.org/-/whoami'
```

You'll get username in response in case of success, `401 Unauthorized` in case if token doesn't exists and `403 Forbidden` in case if your IP address is not whitelisted.

NPM token can be [CIDR-whitelisted](https://docs.npmjs.com/creating-and-viewing-authentication-tokens#creating-tokens-with-the-cli). Thus if you are using token from *non-whitelisted* CIDR you'll get `403 Forbidden` in response. So try to verify NPM token from different IP ranges!.

P.S. Some companies [uses registries other than `registry.npmjs.org`](https://medium.com/bugbountywriteup/one-token-to-leak-them-all-the-story-of-a-8000-npm-token-79b13af182a3). If it's the case replace all `registry.npmjs.org` occurrences with domain name of company's NPM registry.

## [OpsGenie API Key](https://docs.opsgenie.com/docs/api-overview)
```
curl https://api.opsgenie.com/v2/alerts -H 'Authorization: GenieKey API_KEY'
```

## [Keen.io API Key](https://keen.io/docs/api/)

Get all collections for a specific project:

```
curl "https://api.keen.io/3.0/projects/PROJECT_ID/events?api_key=READ_KEY"
```

>Note: Keep the colon at the end of the token to prevent cURL from requesting a password.
Info: The token is always in the following format: sk_live_34charshere, where the 34charshere part contains 34 characters from a-z A-Z 0-9
There is also a test key, which starts with sk_test, but this key is worthless since it is only used for testing purposes and most likely doesn't contain any sensitive info.
The live key, on the other hand, can be used to extract/retrieve a lot of info. Going from charges, to the complete product list.
Keep in mind that you will never be able to get the full credit card information since stripe only gives you like the last 4 digits.
More info / complete docs: https://stripe.com/docs/api/authentication
=======

## [Calendly API Key](https://developer.calendly.com/docs/)

Get user information:

````
curl --header "X-TOKEN: <your_token>" https://calendly.com/api/v1/users/me
````

List Webhook Subscriptions:

````
curl --header "X-TOKEN: <your_token>" https://calendly.com/api/v1/hooks
````

## [Azure Application Insights APP ID and API Key](https://dev.applicationinsights.io/reference)

Get the total number of requests made in last 24 hours:

```
curl -H "x-api-key: {API_Key}" "https://api.applicationinsights.io/v1/apps/{APP_ID}/metrics/requests/count"
```

## [Cypress record key](https://docs.cypress.io/guides/dashboard/projects.html#Record-key)

In order to check `recordKey` validity you'll need `projectId` which is public value that usually can be found at `cypress.json` file. Replace `{recordKey}` and `{projectId}` in JSON body with your values.

```
curl -i -s -k -X $'POST' \
    -H $'x-route-version: 4' -H $'x-os-name: darwin' -H $'x-cypress-version: 5.5.0' -H $'host: api.cypress.io' -H $'accept: application/json' -H $'content-type: application/json' -H $'Content-Length: 1433' -H $'Connection: close' \
    --data-binary $'{\"ci\":{\"params\":null,\"provider\":null},\"specs\":[\"cypress/integration/examples/actions.spec.js\",\"cypress/integration/examples/aliasing.spec.js\",\"cypress/integration/examples/assertions.spec.js\",\"cypress/integration/examples/connectors.spec.js\",\"cypress/integration/examples/cookies.spec.js\",\"cypress/integration/examples/cypress_api.spec.js\",\"cypress/integration/examples/files.spec.js\",\"cypress/integration/examples/local_storage.spec.js\",\"cypress/integration/examples/location.spec.js\",\"cypress/integration/examples/misc.spec.js\",\"cypress/integration/examples/navigation.spec.js\",\"cypress/integration/examples/network_requests.spec.js\",\"cypress/integration/examples/querying.spec.js\",\"cypress/integration/examples/spies_stubs_clocks.spec.js\",\"cypress/integration/examples/traversal.spec.js\",\"cypress/integration/examples/utilities.spec.js\",\"cypress/integration/examples/viewport.spec.js\",\"cypress/integration/examples/waiting.spec.js\",\"cypress/integration/examples/window.spec.js\"],\"commit\":{\"sha\":null,\"branch\":null,\"authorName\":null,\"authorEmail\":null,\"message\":null,\"remoteOrigin\":null,\"defaultBranch\":null},\"group\":null,\"platform\":{\"osCpus\":[],\"osName\":\"darwin\",\"osMemory\":{\"free\":1153744896,\"total\":17179869184},\"osVersion\":\"19.6.0\",\"browserName\":\"Electron\",\"browserVersion\":\"85.0.4183.121\"},\"parallel\":null,\"ciBuildId\":null,\"projectId\":\"{projectId}\",\"recordKey\":\"{recordKey}\",\"specPattern\":null,\"tags\":[\"\"]}' \
    $'https://api.cypress.io/runs'
```

Yes, this request needs to be that big. It'll return `200 OK` with some information about run in case if both `projectId` and `recordKey` are valid, `404 Not Found` with `{"message":"Project not found. Invalid projectId."}` if `projectId` is invalid or `401 Unauthorized` with `{"message":"Invalid Record Key."}` if `recordKey` is invalid.

Example of `projectId` is `1yxykz` and example of `recordKey` is `a216e7b4-4819-4713-b9c2-c5da60a1c48c`.

## [YouTube API Key](https://developers.google.com/youtube/v3/docs/)
Fetch content details for a YouTube channel (The channelId in this case points to PewDiePie's channel).

```
curl -iLk 'https://www.googleapis.com/youtube/v3/activities?part=contentDetails&maxResults=25&channelId=UC-lHJZR3Gqxm24_Vd_AJ5Yw&key={KEY_HERE}'
```


## [ABTasty API Key](https://developers.abtasty.com/server-side.html#authentication)

```
curl "api_endpoint_here" -H "x-api-key: your_api_key"
```

## [Iterable API Key](https://api.iterable.com/api/docs)
Export campaign analytics data in JSON format, one entry per line. Use of either 'range' or 'startDateTime' and 'endDateTime' is required.

```
curl -H "Api_Key: {API_KEY}" https://api.iterable.com/api/export/data.json?dataTypeName=emailSend&range=Today&onlyFields=List.empty
```
## [Amplitude API Keys](https://help.amplitude.com/hc/en-us/articles/205406637-Export-API-Export-Your-Project-s-Event-Data)
The response is a zipped archive of JSON files, with potentially multiple files per hour. Note that events prior to 2014-11-12 will be grouped by day instead of by the hour. If you request data for a time range during which no data has been collected for the project, then you will receive a 404 response from the server.

```
curl -u API_Key:Secret_Key 'https://amplitude.com/api/2/export?start=20200201T5&end=20210203T20' >> yourfilename.zip
```

## [Visual Studio App Center API Token](https://docs.microsoft.com/en-us/appcenter/api-docs/)
   
   1. List all the app projects for the API Token:
  ```
  curl -sX GET  "https://api.appcenter.ms/v0.1/apps" \
 -H "Content-Type: application/json" \
 -H "X-Api-Token: {your_api_token}"
  ```
   2. Fetch the latest app build information for a particular project:
   > Use the `name` and `owner.name` obtained in response in Step [1](#438).
  ```
  curl -sX GET  "https://api.appcenter.ms/v0.1/apps/{owner.name}/{name}/releases/latest" \
-H "Content-Type: application/json" \
-H "X-Api-Token: {your_api_token}"
  ```

## [WeGlot Api Key](https://weglot.com/)
   

```
curl -X POST \
  'https://api.weglot.com/translate?api_key=my_api_key' \
  -H 'Content-Type: application/json' \
  -d '{  
   "l_from":"en",
   "l_to":"fr",
   "request_url":"https://www.website.com/",
   "words":[  
      {"w":"This is a blue car", "t": 1},
      {"w":"This is a black car", "t": 1}
   ]
}'
```

## [PivotalTracker API Token](https://www.pivotaltracker.com/help/api/#top)

   1. List User Information with API Token:
   ```
   curl -X GET -H "X-TrackerToken: $TOKEN" "https://www.pivotaltracker.com/services/v5/me?fields=%3Adefault"
   ```
   
   1. Obtain API Token with Valid User Credentials:
   ```
   curl -s -X GET --user 'USER:PASSWORD' "https://www.pivotaltracker.com/services/v5/me -o pivotaltracker.json"
   jq --raw-output .api_token pivotaltracker.json
   ```
## [LinkedIn OAUTH](https://docs.microsoft.com/en-us/linkedin/shared/authentication/client-credentials-flow?context=linkedin/context)
A successful access token request returns a JSON object containing access_token, expires_in.
```
curl -XPOST -H "Content-type: application/x-www-form-urlencoded" -d 'grant_type=client_credentials&client_id=<client-ID>&client_secret=<client-secret>' 'https://www.linkedin.com/oauth/v2/accessToken'

```


## [Help Scout OAUTH](https://developer.helpscout.com/mailbox-api/overview/authentication/)
A successful access token request returns a JSON object containing token_type, access_token, expires_in.
```
curl -X POST https://api.helpscout.net/v2/oauth2/token \
    --data "grant_type=client_credentials" \
    --data "client_id={application_id}" \
    --data "client_secret={application_secret}"
```


## [Shodan Api Key](https://developer.shodan.io/api/requirements)
```
curl "https://api.shodan.io/shodan/host/8.8.8.8?key=TOKEN_HERE"
```


## [Bazaarvoice Passkey](https://developer.bazaarvoice.com/conversations-api/home)
A Successful Passkey Request returns a JSON object containing company name
```
curl 'https://which-cpv-api.bazaarvoice.com/clientInfo?conversationspasskey=<Passkey>' --insecure 

```

## [Grafana Access Token](https://grafana.com/docs/grafana/latest/developers/http_api/user/)
Grafana API supports Bearer and Basic authorisation schemes. Bearer:
```
curl -s -H "Authorization: Bearer your-api-key" http://your-grafana-server-url.com/api/user
```
Basic:
```
curl -u username:password http://your-grafana-server-url.com/api/user
```

# Contributing

I welcome contributions from the public.

### Using the issue tracker 💡

The issue tracker is the preferred channel for bug reports and features requests.

### Issues and labels 🏷

The bug tracker utilizes several labels to help organize and identify issues.

### Guidelines for bug reports 🐛

Use the GitHub issue search — check if the issue has already been reported.

# ⚠ Legal Disclaimer

This project is made for educational and ethical testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this tool.
