# CPCDS Authorization Server

This project is the authorization server for the [CPCDS Reference Server](https://github.com/carin-alliance/cpcds-server-ri). It supports authorization using OAuth 2.0 in the stand alone SMART app launch sequence.

This server is deployed at http://ec2-18-217-222-36.us-east-2.compute.amazonaws.com:8180/

Note: This is a reference implementation and is intended only to test the CPCDS Server and the CPCDS Client implementations. This authorization server purposefully enables data to be publicly accessible to assist in debugging. Caution should be taken if attempting to use this implementation in a production enviornment. All data sent to the server should be fictional. For more details see "Security" at the bottom of this page.

## Quickstart

The quickest way to get the server up and running is by pulling the built image from docker hub.

```bash
docker pull blangley/cpcds-auth-server
docker run -p 8180:8180 blangley/cpcds-auth-server
```

This will deploy the authorization server to http://localhost:8180.

## Preloaded Users and Clients

The server will automatically include the following Users and Clients when it starts up.

### Users

| ID         | Username   | Password    | Description                                                |
| ---------- | ---------- | ----------- | ---------------------------------------------------------- |
| 1          | user1      | password1   | Account for `Patient/1` from Synthea generated data        |
| 689        | user689    | password689 | Account for `Patient/689` from Synthea generated data      |
| Patient1   | patient1   | password1   | Account for `Patient/Patient1` from IG Examples            |
| PatientEx1 | patientex1 | passwordex1 | Account for `Patient/PatientEx1` from IG Examples          |
| admin      | admin      | 123456789   | Admin account which can access all resources on the server |

### Clients

| ID                                   | RedirectURI                                 | Secret                                                                                                                                                                                                                                                           |
| ------------------------------------ | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| b0c46635-c0b4-448c-a8b9-9bd282d2e05a | http://localhost:4000/login                 | bUYbEj5wpazS8Xv1jyruFKpuXa24OGn9MHuZ3ygKexaI5mhKUIzVEBvbv2uggVf1cW6kYD3cgTbCIGK3kjiMcmJq3OG9bn85Fh2x7JKYgy7Jwagdzs0qufgkhPGDvEoVpImpA4clIhfwn58qoTrfHx86ooWLWJeQh4s0StEMqoxLqboywr8u11qmMHd1xwBLehGXUbqpEBlkelBHDWaiCjkhwZeRe4nVu4o8wSAbPQIECQcTjqYBUrBjHlMx5vXU |
| 6cfecf41-e364-44ab-a06f-77f8b0c56c2b | https://cpcds-client-ri.herokuapp.com/login | XHNdbHQlOrWXQ8eeXHvZal1EDjI3n2ISlqhtP30Zc89Ad2NuzreoorWQ5P8dPrxtk267SJ23mbxlMzjriAGgkaTnm6Y9f1cOas4Z6xhWXxG43bkIKHhawMR6gGDXAuEWc8wXUHteZIi4YCX6E1qAvGdsXS1KBhkUf1CLcGmauhbCMd73CjMugT527mpLnIebuTp4LYDiJag0usCE6B6fYuTWV21AbvydLnLsMsk83T7aobE4p9R0upL2Ph3OFTE1 |

## Building locally with Docker

To start the server simply build and run using docker. The container will automatically build and deploy using a tomcat server.

```bash
git clone https://github.com/carin-alliance/cpcds-auth-server.git
cd cpcds-auth-server
docker build -t cpcds-auth-server .
docker run -p 8180:8180 cpcds-auth-server
```

This will build and deploy the authorization server to http://localhost:8180.

## Manual Build and Run

Clone the repo and build the server:

```bash
git clone https://github.com/carin-alliance/cpcds-auth-server.git
cd cpcds-auth-server
./gradlew installBootDist
./gradlew bootRun
```

This will build and deploy the authorization server to http://localhost:8180.

Note: This has only been tested using Java 11.

## AWS Deployment

This server is hosted on AWS at http://ec2-18-221-169-54.us-east-2.compute.amazonaws.com:8180/. Follow these steps to update it.

1. Build the new docker image `docker build -t blangley/cpcds-auth-server .`
1. Push the image to dockerhub `docker push blangley/cpcds-auth-server`
1. SSH into the AWS sandbox `ssh -i {pem file} ubuntu@ec2-18-221-169-54.us-east-2.compute.amazonaws.com`
1. Pull the new image `sudo docker pull blangley/cpcds-auth-server`.
1. Kill the old image `sudo docker kill {container id}`. To find the container id run `sudo docker ps`.
1. Start the new image `sudo docker run -d -p 8180:8180 blangley/cpcds-auth-server`.

## User and Client Registration

The authorization sequence relies on a valid client and user being registered with the system. In the image of this server on docker hub a few users and clients are already loaded. A web interface is provided at `/register/user` and `/register/client` to register a new user and client respectively. These two interfaces use the underlying POST requests described in the next section to complete the registration process.

## Authorization & Launch Sequence

### POST /register/user

Before the authorization sequence can begin the user must register with the system. The endpoint for this is `/register/user` and the JSON body parameters are:
| Parameter | Value |
| ----------|-------|
| `username`| User created unique identifier for the system |
| `password`| User created password to authenticate |
| `id` | The id of the patient associated with this user

Example:

```
POST HTTP/1.1
http://localhost:8180/register/user
Content-Type: application/json
{
      "username": "user1",
      "password": "password1",
      "patientId": "1"
}
```

The response to the POST is 201 CREATED on success.

### GET /register/user

A web interface is available to register a new user.

### POST /register/client

Before the authorization sequence can begin the client must be registered with the system. The endpoint for this is `/register/client` and the query parameters are:
| Parameter | Value |
|-----------|-------|
| `redirect_uri` | The redirect URI the client will use

Example:

```
POST HTTP/1.1
http://localhost:8180/register/client?redirect_uri=http://localhost:4000/login
```

The response to the post is 201 CREATED on success with the json body:

```json
{
  "id": "a12c5a8a-0288-4502-9190-5ddf79145938",
  "secret": "N3MXICwdkqIbbkhociXxtZJ8HGu4EpHKT7X7IA6M08P1m3px7aIfBDnfdStUfjArJGqQIoWtH4my5XtkZJso9SHSuOlkhcnIqfB8zj6PqVoXbqjt6svPaCtmDR0qiCZq0g8FfqAikI5DbUkKY2LomIwLjx3Qhe7nzuOZgeap4rDU959tHqYpaD11Yvgjk2SfRXZpdkcEURMhsLVvX7AXgsbylaVyy52iwsF8nSNfjtMXenDQhj1Jxr0WlZHisQNQ",
  "redirect": "http://localhost:4000/login"
}
```

### GET /register/client

A web interface is available to register a new client.

### GET /authorization

The first step is to obtain an authorization code from the auth server. The endpoint for this is `/authorization` and the query parameters are:
| Parameter | Value |
| ----------|-------|
| `response_type` | `code` |
| `client_id` | The client id |
| `redirect_uri` | The URI to redirect to with the code |
| `scope` | The [SMART on FHIR Access Scope](http://www.hl7.org/fhir/smart-app-launch/scopes-and-launch-context/index.html) |
| `state` | Unique ID generated by the client for this interaction
| `aud` | The base URL for the CPCDS FHIR server (`http://localhost:8080/cpcds-server/fhir`)

Example:

```
GET http://localhost:8180/authorization?response_type=code&
      client_id=user689&redirect_uri=http://localhost:3000/index&
      scope=patient/*.read&state=12345abc&aud=http://localhost:8180
```

The response to the GET request is a redirection to the provided `redirect_uri` with the following query parameters:
| Parameter | On | Value |
| ----------- | ----| ---- |
| `code` | Success | The authorization code for the client
| `state` | Success | Echo of `state` parameter in the request
| `error` | Failure | Error code defined in [RFC 6749](https://tools.ietf.org/html/rfc6749)

Example:

```
HTTP/1.1 302 Found
Location: http://localhost:3000/index?code=abc123&state=12345abc
```

Note: The authorization code is only valid for 2 minutes.

### POST /token

After obtaining an authorization code it is exchanged for an access token. To obtain an access token (which is valid for 1 hour) use the `/token` endpoint with the following query parameters:
| Parameter | Value |
| ----- | --- |
| `grant_type` | `authorization_code` |
| `code` | The authorization code returned by the `/authorization` endpoint |
| `redirect_uri` | The same `redirect_uri` from the `/authorization` request

The client must also include a basic Authorization header with the value `base64Encode(client_id:client_secret)` and use `Content-Type` of `application/x-www-form-urlencoded`.

Example:

```
POST HTTP/1.1
Authorization: Basic MTpwYXNzd29yZA==
Content-Type: application/x-www-form-urlencoded
http://localhost:8180/token?grant_type=authorization_code&
      code=abc123&redirect_uri=http://localhost:3000/index
```

The response to the POST is a JSON object with the following values:
| Key | Value |
| --- | --- |
| `access_token` | The access token for the protected resource |
| `token_type` | `bearer` |
| `expires_in` | The seconds until expiration (`3600`)

The `access_token` is valid for 1 hour and can be used to query protected resources from the CPCDS Server. For more details on how to use the CPCDS Server view the [README](https://github.com/carin-alliance/cpcds-server-ri).

### GET /.well-known/jwks.json

The public keys used for verifying the signatures are found at this endpoint. For this RI the RSA keys do not rotate and are created at server initialization in `App.java`.

Example:

```
GET http://localhost:8180/.well-known/jwks.json
```

Retuns:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "2542507730329925502019959402417157606871382892503593304032212496853538284138894186312740754437083011799807189636117018396940516735918014461610794552420857",
      "use": "sig",
      "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
      "alg": "RS256",
      "n": "5690166698804597197330905768480486858877596610886363234480576904931540875874759967271069328480055496837733730620168171327423013607454238318286896004712153"
    }
  ]
}
```

## Debug Endpoints

To enable debugging while using this reference implementation three debug endpoints are enabled. These endpoints publicly expose data which is useful for development but should be kept private for a real instance.

### GET /debug/Users

Returns a readonly webpage user interface for the Users table in the database. Columns are USERNAME, PATIENT_ID, PASSWORD, REFRESH_TOKEN, and TIMESTAMP.

### GET /debug/Clients

Returns a readonly webpage user interface for the registered Clients table in the database. Columns are ID, SECRET, REDIRECT_URI, and TIMESTAMP.

### GET /debug/Log

Returns the contents of the log file for the server.

## JWT Token Structure

JWT tokens are used throughout this process to digitally sign the Authorization Code and the Access Token. All JWT tokens in this reference implementation utilize the HS256 algorithm. The structure of the payload for the two types of tokens are shown below:

### Authorization Code Payload Structure

```
{
  "aud": "http://localhost:8180", // Audience is the this auth server
  "iss": "http://localhost:8180", // Issued by this auth server URL
  "redirect_uri": "http://localhost:4000/client", // redirect_uri param from request
  "exp": 1583853744, // Time of expiration (120s after iat)
  "iat": 1583853624, // Issued at time
  "username": "user689", // The login username for this client
  "client_id": "0oa41ji88gUjAKHiE4x6" // The client requesting the authorization
}
```

### Access Token Payload Structure

```
{
  "aud": "http://localhost:8080/cpcds-server/fhir", // Audience is the protected CPCDS server
  "iss": "http://localhost:8180", // Issued by this auth server URL
  "exp": 1583856862, // Time of expiration (3600s after iat)
  "iat": 1583853262, // Issued at time
  "patient_id": "1", // Patient ID for this user
  "client_id": "0oa41ji88gUjAKHiE4x6", // The client requesting the authorization
  "jti": "7f9971da-ea43-4554-b9f7-3157a796175d" // Unique identifier for this token
}
```

## Configuration

The auth server must know the EHR Server endpoint to validate the audience. This can be configured in `App.java` by changing the value of `ehrServer`. The default value is the same base url as this auth server with `:8080/cpcds-server/fhir` as the endpoint.

## Security

Since this code base serves as the reference implementation for the Carin BB IG there are multiple places where potential security vulnerabilities were intentionally made to allow testing developers to debug their code. With these vulnerabilities in place, testing and debugging connections is substantially easier. If this code is to be used for a production enviornment care must be taken to ensure all vulnerabilities are fixed. Below is a list of _some_ of the identified issues. It is your responsibility to make sure all vulnerabilities, including those not listed below, are fixed in a production enviornment.

1. Logger statements print secrets - in places such as `User.java` and `Client.java` the logger displays the hashed password and client secret. Caution should be used any time a secret value is logged. Care should be taken to protect the log files from malicious users.
2. Debug endpoint - the debug endpoint provides public access to the Users and Client table which provides hashed passwords and client secrets. This endpoint also provides public access to the log file. The debug endpoint should be removed for a production enviornment.
3. Managing keys - the RSA keys used to sign and validate the JWT tokens are hard coded in `App.java`. Your implementation must change these keys and ensure they are stored in a secure location. Consider having rotating keys.

This may not be an exhaustive list. The developers of this reference implementations are not responsible for any vulnerabilities in the code base. All use of this repository comes with the understanding this reference implementation is used for testing connections only.
