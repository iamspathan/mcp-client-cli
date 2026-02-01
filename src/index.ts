#!/usr/bin/env node
/**
 * MCP Client CLI - Tests Enterprise Managed Authorization using SDK PR #1328
 *
 * Flow:
 * 1. Start local callback server
 * 2. Open browser for IDP login (PKCE)
 * 3. Receive authorization code via callback
 * 4. Exchange code for ID Token
 * 5. SDK's withCrossAppAccess handles: ID-JAG exchange + JWT Bearer grant
 * 6. Connect to MCP Server with access token
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  applyMiddlewares,
  withCrossAppAccess,
} from '@modelcontextprotocol/client';
import express from 'express';
import open from 'open';
import crypto from 'node:crypto';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Configuration
const config = {
  idpUrl: process.env.IDP_URL || 'http://localhost:4000',
  authServerUrl: process.env.AUTH_SERVER_URL || 'http://localhost:5001',
  mcpServerUrl: process.env.MCP_SERVER_URL || 'http://localhost:5002',
  clientId: process.env.CLIENT_ID || 'agent0',
  clientSecret: process.env.CLIENT_SECRET || 'secret-agent0',
  callbackPort: parseInt(process.env.CALLBACK_PORT || '3333', 10),
  mcpAudience: process.env.MCP_AUDIENCE || 'http://localhost:5002/mcp',
};

const REDIRECT_URI = `http://localhost:${config.callbackPort}/callback`;

// PKCE helpers
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Generate authorization URL
function getAuthorizationUrl(state: string, codeChallenge: string): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email',
    state,
    nonce: crypto.randomUUID(),
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return `${config.idpUrl}/authorize?${params.toString()}`;
}

// Exchange authorization code for tokens
async function exchangeCodeForTokens(
  code: string,
  codeVerifier: string
): Promise<{ idToken: string; accessToken?: string }> {
  const response = await fetch(`${config.idpUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code_verifier: codeVerifier,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${error}`);
  }

  const data = await response.json() as { id_token: string; access_token?: string };
  return {
    idToken: data.id_token,
    accessToken: data.access_token,
  };
}

// Decode JWT for display
function decodeJwt(token: string): Record<string, unknown> {
  try {
    const parts = token.split('.');
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    return { error: 'Failed to decode' };
  }
}

// Main CLI flow
async function main() {
  console.log('\n=== MCP Client CLI (SDK PR #1328 Test) ===\n');
  console.log('Configuration:');
  console.log(`  IDP URL:         ${config.idpUrl}`);
  console.log(`  Auth Server URL: ${config.authServerUrl}`);
  console.log(`  MCP Server URL:  ${config.mcpServerUrl}`);
  console.log(`  MCP Audience:    ${config.mcpAudience}`);
  console.log(`  Client ID:       ${config.clientId}`);
  console.log('');

  // Generate PKCE values
  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Create promise that resolves when we get the auth code
  let resolveAuthCode: (code: string) => void;
  const authCodePromise = new Promise<string>((resolve) => {
    resolveAuthCode = resolve;
  });

  // Start callback server
  const app = express();

  app.get('/callback', (req, res) => {
    const code = req.query.code as string;
    const returnedState = req.query.state as string;
    const error = req.query.error as string;

    if (error) {
      res.send(`<h1>Error</h1><p>${error}</p>`);
      return;
    }

    if (returnedState !== state) {
      res.send('<h1>Error</h1><p>State mismatch</p>');
      return;
    }

    res.send('<h1>Success!</h1><p>You can close this window and return to the terminal.</p>');
    resolveAuthCode(code);
  });

  const server = app.listen(config.callbackPort, () => {
    console.log(`Callback server listening on port ${config.callbackPort}`);
  });

  // Open browser for login
  const authUrl = getAuthorizationUrl(state, codeChallenge);
  console.log('\nOpening browser for IDP login...');
  console.log(`URL: ${authUrl}\n`);
  await open(authUrl);

  // Wait for authorization code
  console.log('Waiting for authorization callback...\n');
  const code = await authCodePromise;
  console.log('Received authorization code!\n');

  // Close callback server
  server.close();

  // Step 1: Exchange code for ID token
  console.log('Step 1: Exchanging authorization code for ID Token...');
  const { idToken } = await exchangeCodeForTokens(code, codeVerifier);
  const idTokenPayload = decodeJwt(idToken);
  console.log(`  Got ID Token for: ${idTokenPayload.email || idTokenPayload.sub}`);
  console.log('');

  // Step 2 & 3: SDK handles ID-JAG exchange and JWT Bearer grant
  console.log('Step 2 & 3: SDK withCrossAppAccess middleware will handle:');
  console.log('  - Token Exchange at IDP -> ID-JAG');
  console.log('  - JWT Bearer at Auth Server -> MCP Access Token');
  console.log('');

  // Create the SDK middleware
  const xaaMiddleware = withCrossAppAccess({
    idpUrl: config.idpUrl,
    idToken: idToken,
    idpClientId: config.clientId,
    idpClientSecret: config.clientSecret,
    mcpAuthorisationServerUrl: config.authServerUrl,
    mcpResourceUrl: config.mcpAudience,
    mcpClientId: config.clientId,
    mcpClientSecret: config.clientSecret,
    scope: ['todos.read', 'mcp.access'],
  });

  // Apply middleware to fetch
  const enhancedFetch = applyMiddlewares(xaaMiddleware)(fetch);

  // Step 4: Connect to MCP Server
  console.log('Step 4: Connecting to MCP Server...');

  const transport = new StreamableHTTPClientTransport(
    new URL(`${config.mcpServerUrl}/mcp`),
    { fetch: enhancedFetch }
  );

  const client = new Client(
    { name: 'mcp-cli-client', version: '1.0.0' },
    { capabilities: {} }
  );

  try {
    await client.connect(transport);
    console.log('  Connected!\n');

    // Get server info
    const serverInfo = client.getServerVersion();
    if (serverInfo) {
      console.log(`MCP Server: ${serverInfo.name} v${serverInfo.version}\n`);
    }

    // List resources
    console.log('Available Resources:');
    const resources = await client.listResources();
    for (const resource of resources.resources) {
      console.log(`  - ${resource.uri}`);
      if (resource.description) {
        console.log(`    ${resource.description}`);
      }
    }
    console.log('');

    // Read first resource
    if (resources.resources.length > 0) {
      const firstUri = resources.resources[0].uri;
      console.log(`Reading resource: ${firstUri}`);
      const content = await client.readResource({ uri: firstUri });
      console.log('Content:');
      for (const item of content.contents) {
        if ('text' in item) {
          console.log(item.text);
        }
      }
    }

    // Disconnect
    await client.close();
    console.log('\nDisconnected from MCP Server.');

  } catch (error) {
    console.error('MCP Connection Error:', error);
    process.exit(1);
  }

  console.log('\n=== Test Complete ===\n');
}

main().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});
