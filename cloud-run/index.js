const { default: fetch } = require("node-fetch");
const { GoogleAuth } = require("google-auth-library");
const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");
const { HttpRequest } = require("@smithy/protocol-http");
const { parseUrl } = require("@smithy/url-parser");
const { SignatureV4 } = require("@smithy/signature-v4");
const { formatUrl } = require("@aws-sdk/util-format-url");
const { Sha256 } = require("@aws-crypto/sha256-js");
const { defaultProvider } = require("@aws-sdk/credential-provider-node");
const axios = require('axios');

// Cloud Run URL without the protocol
const CLOUD_RUN_URL = 'canvas-snapshot-processor-function-1052548303871.us-east4.run.app';
const CLOUD_RUN_FULL_URL = `https://${CLOUD_RUN_URL}`;

// Helper function for consistent logging
function log(message, data = null, isError = false) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    message,
    ...(data && { data: typeof data === 'string' ? data : JSON.stringify(data, null, 2) })
  };
  
  if (isError) {
    console.error(JSON.stringify(logEntry));
  } else {
    console.log(JSON.stringify(logEntry));
  }
}

// Helper function to get AWS credentials
async function getAWSCredentials() {
  log('Getting AWS credentials');
  
  try {
    // Create STS client
    const stsClient = new STSClient({ region: process.env.AWS_REGION || 'us-east-1' });
    
    // Get credentials using the default provider chain
    const credentialsProvider = defaultProvider();
    const credentials = await credentialsProvider();
    
    // Verify credentials by making a GetCallerIdentity call
    const command = new GetCallerIdentityCommand({});
    const response = await stsClient.send(command);
    
    log('Successfully obtained AWS credentials', {
      accountId: response.Account,
      arn: response.Arn,
      region: process.env.AWS_REGION || 'us-east-1'
    });
    
    return {
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: credentials
    };
  } catch (error) {
    log('Error getting AWS credentials', error.message, true);
    throw new Error(`Failed to get AWS credentials: ${error.message}`);
  }
}

// Helper function to validate GCP credentials
function validateGCPCredentials() {
  log('Loading and validating GCP credentials');
  const gcpCreds = require('./gcp-creds.json');
  
  // Check required fields for workload identity federation
  const required = [
    'service_account_impersonation_url'
  ];
  
  const missing = required.filter(key => !gcpCreds[key]);
  
  if (missing.length > 0) {
    throw new Error(`GCP credentials missing required fields: ${missing.join(', ')}`);
  }
  
  // Extract service account email from the impersonation URL
  const serviceAccount = gcpCreds.service_account_impersonation_url
    .split('/')
    .pop()
    .split(':')[0];
  
  // Construct the correct impersonation URL
  const impersonationUrl = `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${serviceAccount}`;
  
  log('GCP credentials validated successfully', {
    serviceAccount,
    impersonationUrl
  });
  
  return { gcpCreds, serviceAccount, impersonationUrl };
}

// Create AWS token for Google STS exchange
async function createAWSToken() {
  try {
    log('Starting AWS token creation');
    const { region, credentials } = await getAWSCredentials();
    const gcpCreds = require('./gcp-creds.json');
    
    // Determine the workload identity resource
    const workloadIdentityResource = gcpCreds.workforce_pool_user_project ?
      `//iam.googleapis.com/projects/${gcpCreds.workforce_pool_user_project}/locations/global/workloadIdentityPools/${gcpCreds.workload_identity_pool_id}/providers/${gcpCreds.workload_identity_pool_provider_id}` :
      gcpCreds.audience;
    
    log('Using workload identity resource', { workloadIdentityResource });

    // Create and sign the AWS request
    const url = parseUrl(`https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15`);
    
    // Get current timestamp in ISO format
    const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    
    // Create the request object with minimal headers - let SignatureV4 add the rest
    const request = new HttpRequest({
      ...url,
      method: 'POST',
      headers: {
        'host': 'sts.amazonaws.com',
        'x-goog-cloud-target-resource': workloadIdentityResource
      }
    });

    log('Created initial AWS request', {
      method: request.method,
      url: formatUrl(request),
      headers: request.headers
    });

    // Sign the request
    const signer = new SignatureV4({
      credentials: credentials,
      region: region,
      service: 'sts',
      sha256: Sha256,
      applyChecksum: false
    });

    log('Signing AWS request');
    const signedRequest = await signer.sign(request);
    log('Request signed successfully');

    // Create token in the format expected by Google STS
    const token = {
      url: formatUrl(signedRequest),
      method: signedRequest.method,
      headers: []
    };

    // Add headers in specific order
    const headerOrder = [
      'host',
      'content-type',
      'x-amz-date',
      'x-amz-security-token',
      'x-goog-cloud-target-resource',
      'authorization'
    ];

    // Process headers in the specified order
    headerOrder.forEach(headerKey => {
      const value = signedRequest.headers[headerKey] || signedRequest.headers[headerKey.toLowerCase()];
      if (value) {
        token.headers.push({
          key: headerKey === 'host' ? 'Host' :
               headerKey === 'content-type' ? 'Content-Type' :
               headerKey === 'x-amz-date' ? 'X-Amz-Date' :
               headerKey === 'x-amz-security-token' ? 'X-Amz-Security-Token' :
               headerKey === 'x-goog-cloud-target-resource' ? 'X-Goog-Cloud-Target-Resource' :
               headerKey === 'authorization' ? 'Authorization' : headerKey,
          value: Array.isArray(value) ? value[0] : value
        });
      }
    });

    // URL encode the token
    const encodedToken = encodeURIComponent(JSON.stringify(token));
    log('Token created successfully', {
      token: {
        ...token,
        headers: token.headers.map(h => ({
          key: h.key,
          value: h.key === 'Authorization' || h.key === 'X-Amz-Security-Token' ? '[REDACTED]' : h.value
        }))
      }
    });

    return encodedToken;
  } catch (error) {
    log('Error creating AWS token', error.message, true);
    throw error;
  }
}

async function getGoogleAccessToken() {
  try {
    log('Starting Google token acquisition');
    const { gcpCreds, serviceAccount, impersonationUrl } = validateGCPCredentials();
    
    // Get AWS token
    const awsToken = await createAWSToken();
    log('AWS token generated successfully');

    // Exchange AWS credentials for Google federated token
    log('Exchanging AWS credentials for Google federated token');
    const stsPayload = {
      audience: gcpCreds.audience,
      grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
      requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      subjectTokenType: gcpCreds.subject_token_type,
      subjectToken: awsToken
    };
    
    log('Making STS exchange request', {
      url: 'https://sts.googleapis.com/v1/token',
      payload: { ...stsPayload, subjectToken: '[REDACTED]' }
    });

    const federatedTokenResponse = await fetch('https://sts.googleapis.com/v1/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(stsPayload)
    });

    if (!federatedTokenResponse.ok) {
      const errorText = await federatedTokenResponse.text();
      log('STS exchange failed', {
        status: federatedTokenResponse.status,
        statusText: federatedTokenResponse.statusText,
        error: errorText
      }, true);
      throw new Error(`Failed to exchange token: ${errorText}`);
    }

    const federatedToken = await federatedTokenResponse.json();
    log('Successfully obtained federated token');

    // Impersonate service account
    log('Impersonating service account', { 
      serviceAccount,
      impersonationUrl
    });

    // Use correct format for generateIdToken API
    const impersonationPayload = {
      delegates: [],
      audience: CLOUD_RUN_URL, // Use the Cloud Run URL without protocol
      includeEmail: true
    };

    log('Generating ID token with payload', {
      ...impersonationPayload,
      audience: impersonationPayload.audience
    });

    const impersonationResponse = await fetch(
      `${impersonationUrl}:generateIdToken`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${federatedToken.access_token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(impersonationPayload)
      }
    );

    if (!impersonationResponse.ok) {
      const errorText = await impersonationResponse.text();
      log('Service account impersonation failed', {
        status: impersonationResponse.status,
        statusText: impersonationResponse.statusText,
        error: errorText,
        payload: impersonationPayload
      }, true);
      throw new Error(`Failed to impersonate service account: ${errorText}`);
    }

    const impersonatedToken = await impersonationResponse.json();
    
    if (!impersonatedToken.token) {
      log('ID token missing from response', {
        response: impersonatedToken
      }, true);
      throw new Error('ID token missing from impersonation response');
    }

    log('Successfully obtained impersonated ID token', {
      expiresAt: impersonatedToken.expireTime,
      token: impersonatedToken
    });

    return impersonatedToken.token;
  } catch (error) {
    log('Error in getGoogleAccessToken', error.message, true);
    throw error;
  }
}

// Main handler function
exports.handler = async (event, context) => {
  try {
    log('Lambda function started', { event });
    
    // Get Google ID token
    const idToken = await getGoogleAccessToken();
    log('Successfully obtained Google ID token');

    // Call Cloud Run endpoint
    const cloudRunUrl = `${CLOUD_RUN_FULL_URL}/process`;
    
    log('Calling Cloud Run endpoint', { 
      url: cloudRunUrl,
      method: 'POST',
      tokenLength: idToken.length
    });

    const response = await axios({
      method: 'POST',
      url: cloudRunUrl,
      headers: {
        'Authorization': `Bearer ${idToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Cloud-Trace-Context': context.awsRequestId || 'unknown'
      },
      data: event
    });

    log('Cloud Run request completed successfully', { 
      status: response.status,
      headers: response.headers
    });

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(response.data)
    };
  } catch (error) {
    log('Lambda function failed', error.message, true);
    if (error.response) {
      log('Cloud Run error details', {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data
      }, true);
    }
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        error: error.message,
        requestId: context?.awsRequestId
      })
    };
  }
}
