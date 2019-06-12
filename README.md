<p align="center">
  <img src="https://user-images.githubusercontent.com/18099289/56750563-558a9400-6784-11e9-8175-ee2a19ee9d75.png" width="300px">
</p>
</br>

KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid.

# Table of Contents

- [Algolia API key](#Algolia-API-key)
- [AWS Access Key ID and Secret](#AWS-Access-Key-ID-and-Secret)
- [Branch.io Key and Secret](#BranchIO-Key-and-Secret)
- [DataDog API key](#DataDog-API-key)
- [Deviant Art Access Token](#Deviant-Art-Access-Token)
- [Deviant Art Secret](#Deviant-Art-Secret)
- [Dropbox API](#Dropbox-API)
- [Facebook Access Token  ](#Facebook-Access-Token)
- [Facebook AppSecret](#Facebook-AppSecret)
- [Firebase](#Firebase)
- [GitHub private SSH key](#GitHub-private-SSH-key)
- [Github Token](#Github-Token)
- [Google Cloud Messaging (GCM)](#Google-Cloud-Messaging)
- [Google Maps API key](#Google-Maps-API-key)
- [Heroku API key](#Heroku-API-key)
- [MailGun Private Key](#MailGun-Private-Key)
- [MailChimp API Key](#MailChimp-API-Key)
- [Microsoft Shared Access Signatures (SAS)](#Microsoft-Shared-Access-Signatures-(SAS))
- [Microsoft Azure Tenant](#Microsoft-Azure-Tenant)
- [pagerduty API token](#pagerduty-API-token)
- [Pendo Integration Key](#Pendo-Integration-Key)
- [Salesforce API key](#Salesforce-API-key)
- [Square](#Square)
- [SauceLabs Username and access Key](#SauceLabs-Username-and-access-Key)
- [SendGrid API Token](#SendGrid-API-Token)
- [Slack API token](#Slack-API-token)
- [Slack Webhook](#Slack-Webhook)
- [Travis CI API token](#Travis-CI-API-token)
- [Twilio Account_sid and Auth token](#Twilio-Account_sid-and-Auth-token)
- [Twitter API Secret](#Twitter-API-Secret)
- [Twitter Bearer token](#Twitter-Bearer-token)
- [WPEngine API Key](#WPEngine-API-Key)
- [WakaTime API Key](#WakaTime-API-Key)
- [Zapier Webhook Token](#Zapier-Webhook-Token)
- [Bit.ly Access token](#Bitly-Access-token)
- [Buildkite Access token](#Buildkite-Access-token)
- [Asana Access token](#Asana-Access-Token)
- [Zendesk Access token](#Zendesk-Access-Token)
- [Spotify Access Token](#Spotify-Access-Token)


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

1. obtain ID token and refresh token from custom token and API key: `curl -s -XPOST -H 'content-type: application/json' -d '{"custom_token":":custom_token"}' 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=:api_key'`
2. exchange ID token for auth token: `curl -s -XPOST -H 'content-type: application/json' -d '{"idToken":":id_token"}' https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=:api_key'`

## [Github Token](https://developer.github.com/v3/)
```
curl -s -u "hehe:TOKEN_HERE" https://api.github.com/user
curl -s -H "Authorization: token TOKEN_HERE" "https://api.github.com/users/USERNAME_HERE/orgs
```

## [Google Cloud Messaging](https://developers.google.com/cloud-messaging/)
```
curl -s -X POST --header "Authorization: key=AI..." --header "Content-Type:application/json" 'https://gcm-http.googleapis.com/gcm/send' -d '{"registration_ids":["1"]}'
```

## GitHub private SSH key

SSH private keys can be tested against github.com to see if they are registered against an existing user account. If the key exists the username corresponding to the key will be provided. ([source](https://github.com/streaak/keyhacks/issues/2))

```
$ ssh -i <path to SSH private key> -T git@github.com
Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.
```

## [Twilio Account_sid and Auth token](https://www.twilio.com/docs/iam/api/account)
```
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Keys.json' -u ACCOUNT_SID:AUTH_TOKEN
```

## [Twitter API Secret](https://developer.twitter.com/en/docs/basics/authentication/guides/bearer-tokens.html)
```
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

## [Twitter Bearer token](https://developer.twitter.com/en/docs/accounts-and-users/subscribe-account-activity/api-reference/aaa-premium)
```
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
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

## [SendGrid API Token](https://sendgrid.com/docs/API_Reference/api_v3.html)
```
curl -X "GET" "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer SENDGRID_TOKEN-HERE" -H "Content-Type: application/json"
```

## [Square](https://squareup.com/)
**Detection:**

app id / client secret:  `sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`
auth token: `EAAA[a-zA-Z0-9]{60}`

**Test App id & client secret:**
```
curl "https://squareup.com/oauth2/revoke" -d '{"access_token":"[RANDOM_STRING]","client_id":"[APP_ID]"}'  -H "Content-Type: application/json" -H "Authorization: Client [CLIENT_SECRET]"
```

Valid:
```
empty
```

Not valid:
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

Valid:
```
{"locations":[{"id":"CBASELqoYPXr7RtT-9BRMlxGpfcgAQ","name":"Coffee \u0026 Toffee SF","address":{"address_line_1":"1455 Market Street","locality":"San Francisco","administrative_district_level_1":"CA","postal_code":"94103","country":"US"},"timezone":"America/Los_Angeles"........
```

Not valid:
```
{"errors":[{"category":"AUTHENTICATION_ERROR","code":"UNAUTHORIZED","detail":"This request could not be authorized."}]}
```

## Dropbox API
```
curl -X POST https://api.dropboxapi.com/2/users/get_current_account --header "Authorization: Bearer TOKEN_HERE"
```

## AWS Access Key ID and Secret

Add the new `access_key_id` and `secret` within `~/.aws/credentials` file as a new user (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html).

```
$ aws s3 ls --profile username_picked
$ aws s3 cp test.txt s3://bucket_belonging_to_the_company --profile username_picked
```

## [MailGun Private Key](https://documentation.mailgun.com/en/latest/api_reference.html)
```
curl --user 'api:key-PRIVATEKEYHERE' "https://api.mailgun.net/v3/domains"
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

## [Heroku API key](https://devcenter.heroku.com/articles/platform-api-quickstart)
```
curl -X POST https://api.heroku.com/apps -H "Accept: application/vnd.heroku+json; version=3" -H "Authorization: Bearer API_KEY_HERE"
```

## [Salesforce API key](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/quickstart_oauth.htm)
```
curl https://instance_name.salesforce.com/services/data/v20.0/ -H 'Authorization: Bearer access_token_here'
```
## [Algolia API key](https://www.algolia.com/doc/rest-api/search/#overview)

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

## [pagerduty API token](https://support.pagerduty.com/docs/using-the-api)
```
curl -H "Accept: application/vnd.pagerduty+json;version=2"  -H "Authorization: Token token=TOKEN_HERE" -X GET  "https://api.pagerduty.com/schedules"
```

## [BrowserStack ACCESSKEY](https://www.browserstack.com/automate/rest-api)
```
curl -u "USERNAME:ACCESS_KEY" https://api.browserstack.com/automate/plan.json
```

## [Google Maps API key](https://developers.google.com/maps/documentation/javascript/get-api-key)

Visit the following URL to check for validity
```
https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key=KEY_HERE
https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=12&size=2500x2000&maptype=roadmap&key=KEY_HERE
```

## [Branch.IO Key and Secret](https://docs.branch.io/pages/apps/deep-linking-api/#app-read)

Visit the following URL to check for validity
```
https://api2.branch.io/v1/app/KEY_HERE?branch_secret=SECRET_HERE
```

## [Bit.ly Access token](https://dev.bitly.com/authentication.html)

Visit the following URL to check for validity
```
https://api-ssl.bitly.com/v3/shorten?access_token=ACCESS_TOKEN&longUrl=https://www.google.com
```

## [Buildkite Access token](https://buildkite.com/docs/apis/rest-api)
```
curl -H "Authorization: Bearer ACCESS_TOKEN" \
https://api.buildkite.com/v2/user
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

## [MailChimp API Key](https://developer.mailchimp.com/documentation/mailchimp/reference/overview/)
```
curl --request GET --url 'https://<dc>.api.mailchimp.com/3.0/' --user 'anystring:<API_KEY>' --include
```

## [WPEngine API Key](https://wpengineapi.com/)

This issue can be further exploited by checking out @hateshape 's gist [here](https://gist.github.com/hateshape/2e671ea71d7c243fac7ebf51fb738f0a)

```
curl "https://api.wpengine.com/1.2/?method=site&account_name=ACCOUNT_NAME&wpe_apikey=WPENGINE_APIKEY"
```

## [DataDog API key](https://docs.datadoghq.com/api/)
```
curl "https://api.datadoghq.com/api/v1/dashboard?api_key=<api_key>&application_key=<application_key>"
```

## [Travis CI API token](https://developer.travis-ci.com/gettingstarted)

```
curl -H "Travis-API-Version: 3" -H "Authorization: token <TOKEN>" https://api.travis-ci.com/user
```

## [WakaTime API Key](https://wakatime.com/developers)
```
curl "https://wakatime.com/api/v1/users/current/projects/?api_key=KEY_HERE"
```

## [Spotify Access Token](https://developer.spotify.com/documentation/general/guides/authorization-guide/)
```
curl -H "Authorization: Bearer <ACCESS_TOKEN>" https://api.spotify.com/v1/me
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
