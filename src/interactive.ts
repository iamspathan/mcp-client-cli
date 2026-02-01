#!/usr/bin/env node
/**
 * Interactive MCP Client with Claude AI - Multi-Server Support
 *
 * An AI-powered CLI that uses Claude to interact with multiple MCP servers.
 * Authenticates once, connects to all servers at startup (XAA happens here),
 * then routes tool calls to the appropriate server using existing connections.
 */

import Anthropic from '@anthropic-ai/sdk';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  applyMiddlewares,
  withCrossAppAccess,
} from '@modelcontextprotocol/client';
import * as client from 'openid-client';
import express from 'express';
import open from 'open';
import readline from 'node:readline';
import dotenv from 'dotenv';
import chalk from 'chalk';
import ora from 'ora';

dotenv.config();

// OAuth Protected Resource Metadata (RFC 9470)
interface OAuthProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported?: string[];
  scopes_supported?: string[];
  resource_documentation?: string;
}

// Tool definition for configuration
interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// Resource definition for configuration
interface ResourceDefinition {
  uri: string;
  name: string;
  description?: string;
}

// MCP Server configuration with known tools
interface McpServerConfig {
  name: string;
  url: string;
  authServerUrl?: string;  // Can be auto-discovered
  audience?: string;
  scopes?: string[];
  // Pre-configured tools (optional - can also be fetched from metadata endpoint)
  tools?: ToolDefinition[];
  resources?: ResourceDefinition[];
}

// Connected MCP Server (lazy - only created when needed)
interface ConnectedMcpServer {
  config: McpServerConfig;
  client: Client;
  oauthMetadata?: OAuthProtectedResourceMetadata;
}

// Global configuration
const config = {
  idpUrl: process.env.IDP_URL || 'http://localhost:4000',
  clientId: process.env.CLIENT_ID || 'mcp-tester',
  clientSecret: process.env.CLIENT_SECRET || 'secret-mcp-tester',
  callbackPort: parseInt(process.env.CALLBACK_PORT || '3333', 10),
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
};

// MCP Servers configuration - with pre-defined tools for lazy loading
const mcpServers: McpServerConfig[] = [
  {
    name: process.env.MCP_SERVER_1_NAME || 'qrty',
    url: process.env.MCP_SERVER_1_URL || 'https://mcp.qrty.page',
    authServerUrl: process.env.MCP_SERVER_1_AUTH_URL,  // Auto-discovered if not set
    audience: process.env.MCP_SERVER_1_AUDIENCE,
    scopes: process.env.MCP_SERVER_1_SCOPES?.split(','),
    // Tools will be fetched from /.well-known/mcp-manifest or similar
  },
  {
    name: process.env.MCP_SERVER_2_NAME || 'xaa-dev',
    url: process.env.MCP_SERVER_2_URL || 'https://mcp.xaa.dev',
    authServerUrl: process.env.MCP_SERVER_2_AUTH_URL || 'https://auth.resource.xaa.dev',
    audience: process.env.MCP_SERVER_2_AUDIENCE || 'https://mcp.xaa.dev/mcp',
    scopes: process.env.MCP_SERVER_2_SCOPES?.split(',') || ['todos.read', 'mcp.access'],
    // Tools will be fetched from /.well-known/mcp-manifest or similar
  },
].filter(s => s.url);

const REDIRECT_URI = `http://localhost:${config.callbackPort}/callback`;

// Lazy connection state
let idToken: string | null = null;
const connectedServers = new Map<string, ConnectedMcpServer>();
const serverConfigs = new Map<string, McpServerConfig>();
const toolServerMap = new Map<string, string>();
const resourceServerMap = new Map<string, string>();

// All known tools and resources (from metadata, not connection)
const allTools: ToolDefinition[] = [];
const allResources: ResourceDefinition[] = [];

// Discover OAuth Protected Resource Metadata (RFC 9470)
async function discoverOAuthMetadata(mcpServerUrl: string): Promise<OAuthProtectedResourceMetadata | null> {
  try {
    const baseUrl = new URL(mcpServerUrl);
    const wellKnownUrl = `${baseUrl.origin}/.well-known/oauth-protected-resource`;

    const response = await fetch(wellKnownUrl);
    if (!response.ok) {
      return null;
    }

    const metadata = await response.json() as OAuthProtectedResourceMetadata;
    return metadata;
  } catch {
    return null;
  }
}

// Fetch MCP server manifest (tools/resources without full connection)
async function fetchServerManifest(serverConfig: McpServerConfig): Promise<{ tools: ToolDefinition[], resources: ResourceDefinition[] }> {
  try {
    // Try to fetch from well-known endpoint first
    const manifestUrl = `${serverConfig.url}/.well-known/mcp-manifest`;
    const response = await fetch(manifestUrl);

    if (response.ok) {
      const manifest = await response.json() as { tools?: ToolDefinition[], resources?: ResourceDefinition[] };
      return {
        tools: manifest.tools || [],
        resources: manifest.resources || [],
      };
    }
  } catch {
    // Manifest endpoint not available
  }

  // Fall back to configured tools/resources
  return {
    tools: serverConfig.tools || [],
    resources: serverConfig.resources || [],
  };
}

// OAuth flow using openid-client library
async function authenticate(): Promise<string> {
  const spinner = ora('Discovering OIDC configuration...').start();

  // Discover OIDC configuration from the IDP
  const issuerUrl = new URL(config.idpUrl);
  const oidcConfig = await client.discovery(issuerUrl, config.clientId, config.clientSecret);

  spinner.text = 'Starting authentication...';

  // Generate PKCE code verifier (openid-client handles challenge internally)
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

  // Generate state and nonce for security
  const state = client.randomState();
  const nonce = client.randomNonce();

  // Build authorization URL
  const authParams = new URLSearchParams({
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  });

  const authUrl = client.buildAuthorizationUrl(oidcConfig, authParams);

  // Start local server to receive callback
  let resolveCallback: (url: URL) => void;
  const callbackPromise = new Promise<URL>((resolve) => {
    resolveCallback = resolve;
  });

  const app = express();
  app.get('/callback', (req, res) => {
    const callbackUrl = new URL(req.url, `http://localhost:${config.callbackPort}`);

    res.send(`
      <html>
        <body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e;">
          <div style="text-align: center; color: white;">
            <h1 style="color: #4ade80;">Authentication Successful!</h1>
            <p>You can close this window and return to the terminal.</p>
          </div>
        </body>
      </html>
    `);
    resolveCallback(callbackUrl);
  });

  const server = app.listen(config.callbackPort);

  spinner.text = 'Opening browser for login...';
  await open(authUrl.href);

  spinner.text = 'Waiting for authentication...';
  const callbackUrl = await callbackPromise;
  server.close();

  spinner.text = 'Exchanging code for tokens...';

  // Exchange authorization code for tokens using openid-client
  const tokens = await client.authorizationCodeGrant(oidcConfig, callbackUrl, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  });

  const idTokenValue = tokens.id_token;
  if (!idTokenValue) {
    throw new Error('No ID token received');
  }

  // Get claims from ID token for display
  const claims = tokens.claims();
  const userEmail = claims?.email || claims?.sub || 'unknown';
  spinner.succeed(`Authenticated as ${chalk.cyan(userEmail)}`);
  console.log(chalk.gray('  ID token stored for Cross-App Access (XAA) - connections are lazy'));

  return idTokenValue;
}

// Connect to a single MCP server ON DEMAND (lazy connection with XAA)
async function connectToServer(serverName: string): Promise<ConnectedMcpServer> {
  // Check if already connected
  const existing = connectedServers.get(serverName);
  if (existing) {
    return existing;
  }

  const serverConfig = serverConfigs.get(serverName);
  if (!serverConfig) {
    throw new Error(`Unknown server: ${serverName}`);
  }

  if (!idToken) {
    throw new Error('Not authenticated');
  }

  console.log(chalk.yellow(`  → Connecting to ${serverName} (XAA flow starting)...`));

  // Discover OAuth metadata if auth server not configured
  let oauthMetadata: OAuthProtectedResourceMetadata | null = null;
  if (!serverConfig.authServerUrl) {
    oauthMetadata = await discoverOAuthMetadata(serverConfig.url);
    if (!oauthMetadata) {
      throw new Error(`Failed to discover OAuth metadata for ${serverName}`);
    }
  }

  // Determine auth configuration
  const authServerUrl = serverConfig.authServerUrl || oauthMetadata?.authorization_servers?.[0];
  const resourceUrl = serverConfig.audience || oauthMetadata?.resource || serverConfig.url;
  const scopes = serverConfig.scopes || oauthMetadata?.scopes_supported || ['mcp.access'];

  if (!authServerUrl) {
    throw new Error(`No authorization server for ${serverName}`);
  }

  // Create XAA middleware and connect
  const xaaMiddleware = withCrossAppAccess({
    idpUrl: config.idpUrl,
    idToken,
    idpClientId: config.clientId,
    idpClientSecret: config.clientSecret,
    mcpAuthorisationServerUrl: authServerUrl,
    mcpResourceUrl: resourceUrl,
    mcpClientId: config.clientId,
    mcpClientSecret: config.clientSecret,
    scope: scopes,
  });

  const enhancedFetch = applyMiddlewares(xaaMiddleware)(fetch);

  const transport = new StreamableHTTPClientTransport(
    new URL(`${serverConfig.url}/mcp`),
    { fetch: enhancedFetch }
  );

  const client = new Client(
    { name: 'mcp-interactive-cli', version: '1.0.0' },
    { capabilities: {} }
  );

  await client.connect(transport);

  const connectedServer: ConnectedMcpServer = {
    config: serverConfig,
    client,
    oauthMetadata: oauthMetadata || undefined,
  };

  connectedServers.set(serverName, connectedServer);
  console.log(chalk.green(`  ✔ Connected to ${serverName} via XAA`));

  return connectedServer;
}

// Discover tools from all servers (requires connection for now, but only once per server)
async function discoverServerCapabilities(): Promise<void> {
  const spinner = ora('Discovering MCP server capabilities...').start();

  for (const serverConfig of mcpServers) {
    spinner.text = `Checking ${serverConfig.name}...`;
    serverConfigs.set(serverConfig.name, serverConfig);

    try {
      // First try to get manifest without connection
      const manifest = await fetchServerManifest(serverConfig);

      if (manifest.tools.length > 0 || manifest.resources.length > 0) {
        // Use manifest data
        for (const tool of manifest.tools) {
          allTools.push(tool);
          toolServerMap.set(tool.name, serverConfig.name);
        }
        for (const resource of manifest.resources) {
          allResources.push(resource);
          resourceServerMap.set(resource.uri, serverConfig.name);
        }
        console.log(chalk.gray(`  ${serverConfig.name}: ${manifest.tools.length} tools, ${manifest.resources.length} resources (from manifest)`));
      } else {
        // No manifest - we need to connect to discover
        // For now, connect and discover, then disconnect
        // In production, you might want to cache this or use a manifest endpoint
        spinner.text = `Connecting to ${serverConfig.name} to discover capabilities...`;

        const server = await connectToServer(serverConfig.name);

        try {
          const toolsResult = await server.client.listTools();
          for (const t of toolsResult.tools) {
            const tool: ToolDefinition = {
              name: t.name,
              description: t.description || '',
              inputSchema: t.inputSchema as Record<string, unknown>,
            };
            allTools.push(tool);
            toolServerMap.set(t.name, serverConfig.name);
          }
        } catch {
          // Server might not support tools
        }

        try {
          const resourcesResult = await server.client.listResources();
          for (const r of resourcesResult.resources) {
            const resource: ResourceDefinition = {
              uri: r.uri,
              name: r.name,
              description: r.description,
            };
            allResources.push(resource);
            resourceServerMap.set(r.uri, serverConfig.name);
          }
        } catch {
          // Server might not support resources
        }

        const toolCount = allTools.filter(t => toolServerMap.get(t.name) === serverConfig.name).length;
        const resourceCount = allResources.filter(r => resourceServerMap.get(r.uri) === serverConfig.name).length;
        console.log(chalk.gray(`  ${serverConfig.name}: ${toolCount} tools, ${resourceCount} resources`));
      }
    } catch (error) {
      spinner.text = `Failed to get capabilities for ${serverConfig.name}`;
      console.error(chalk.red(`  ${serverConfig.name}: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  }

  spinner.succeed(`Discovered ${allTools.length} tools, ${allResources.length} resources across ${mcpServers.length} server(s)`);
}

// Convert tools to Claude format
function toolsToClaudeFormat(): Anthropic.Tool[] {
  const claudeTools: Anthropic.Tool[] = [];

  // Resource tools
  if (allResources.length > 0) {
    claudeTools.push({
      name: 'list_resources',
      description: 'List all available MCP resources from all servers',
      input_schema: {
        type: 'object' as const,
        properties: {},
        required: [],
      },
    });

    claudeTools.push({
      name: 'read_resource',
      description: `Read content from an MCP resource. Available: ${allResources.map((r) => `${r.uri} [${resourceServerMap.get(r.uri)}]`).join(', ')}`,
      input_schema: {
        type: 'object' as const,
        properties: {
          uri: {
            type: 'string',
            description: 'The URI of the resource to read',
            enum: allResources.map((r) => r.uri),
          },
        },
        required: ['uri'],
      },
    });
  }

  // MCP tools
  for (const tool of allTools) {
    const serverName = toolServerMap.get(tool.name);
    claudeTools.push({
      name: tool.name,
      description: `[${serverName}] ${tool.description || `MCP tool: ${tool.name}`}`,
      input_schema: tool.inputSchema as Anthropic.Tool['input_schema'],
    });
  }

  return claudeTools;
}

// Handle tool calls - LAZY CONNECTION HERE
async function handleToolCall(
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  try {
    // Handle built-in resource tools
    if (toolName === 'list_resources') {
      return JSON.stringify(
        allResources.map((r) => ({
          uri: r.uri,
          name: r.name,
          description: r.description,
          server: resourceServerMap.get(r.uri),
        })),
        null,
        2
      );
    }

    if (toolName === 'read_resource') {
      const uri = toolInput.uri as string;
      const serverName = resourceServerMap.get(uri);

      if (!serverName) {
        return `Error: Unknown resource URI: ${uri}`;
      }

      const server = connectedServers.get(serverName);
      if (!server) {
        return `Error: Server ${serverName} not connected`;
      }

      console.log(chalk.gray(`  → ${serverName}`));
      const result = await server.client.readResource({ uri });
      const contents = result.contents.map((c) => {
        if ('text' in c) return c.text;
        if ('blob' in c) return `[Binary data: ${c.mimeType}]`;
        return '[Unknown content]';
      });
      return contents.join('\n');
    }

    // Handle MCP tools - use existing connection
    const serverName = toolServerMap.get(toolName);

    if (!serverName) {
      return `Error: Unknown tool: ${toolName}`;
    }

    const server = connectedServers.get(serverName);
    if (!server) {
      return `Error: Server ${serverName} not connected`;
    }

    console.log(chalk.gray(`  → ${serverName}`));
    const result = await server.client.callTool({ name: toolName, arguments: toolInput });
    if (result.content && Array.isArray(result.content)) {
      return result.content
        .map((c) => {
          if ('text' in c) return c.text;
          return JSON.stringify(c);
        })
        .join('\n');
    }
    return JSON.stringify(result, null, 2);
  } catch (error) {
    return `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
  }
}

// Interactive chat loop
async function runInteractiveChat(anthropic: Anthropic) {
  const conversationHistory: Anthropic.MessageParam[] = [];
  const tools = toolsToClaudeFormat();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  const prompt = (query: string): Promise<string> =>
    new Promise((resolve) => {
      if (process.stdin.isPaused()) {
        process.stdin.resume();
      }
      process.stdout.write('\r\x1b[K');
      rl.question(query, (answer) => {
        resolve(answer);
      });
    });

  console.log('\n' + chalk.bold.green('=== MCP Interactive Chat ==='));
  console.log(chalk.gray('Chat with Claude about your MCP resources.'));
  console.log(chalk.gray('Commands: /servers, /resources, /tools, /clear, /logout, /quit\n'));

  const serverList = mcpServers.map(s => {
    const toolCount = allTools.filter(t => toolServerMap.get(t.name) === s.name).length;
    const resourceCount = allResources.filter(r => resourceServerMap.get(r.uri) === s.name).length;
    return `- ${s.name}: ${toolCount} tools, ${resourceCount} resources`;
  }).join('\n');

  const resourceList = allResources
    .map((r) => `- ${r.uri} [${resourceServerMap.get(r.uri)}]: ${r.description || r.name}`)
    .join('\n');

  const systemPrompt = `You are a helpful assistant that can interact with multiple MCP servers.
All servers are connected and ready.

Connected MCP Servers:
${serverList}

Available resources:
${resourceList || 'None'}

When users ask about their data, use the appropriate tools.
Tool descriptions show which server they belong to in brackets [server_name].
Be concise and helpful in your responses.`;

  while (true) {
    const userInput = await prompt(chalk.blue('You: '));

    if (!userInput.trim()) continue;

    // Handle commands
    if (userInput.startsWith('/')) {
      const cmd = userInput.slice(1).toLowerCase();
      if (cmd === 'quit' || cmd === 'exit' || cmd === 'q') {
        console.log(chalk.yellow('\nGoodbye!'));
        break;
      }
      if (cmd === 'clear') {
        conversationHistory.length = 0;
        console.log(chalk.gray('Conversation cleared.\n'));
        continue;
      }
      if (cmd === 'servers') {
        console.log(chalk.cyan('\nConnected Servers:'));
        for (const [name, server] of connectedServers) {
          const toolCount = allTools.filter(t => toolServerMap.get(t.name) === name).length;
          const resourceCount = allResources.filter(r => resourceServerMap.get(r.uri) === name).length;
          console.log(`  ${chalk.bold(name)} ${chalk.green('●')}`);
          console.log(`    URL: ${chalk.gray(server.config.url)}`);
          console.log(`    Tools: ${toolCount}, Resources: ${resourceCount}`);
        }
        console.log('');
        continue;
      }
      if (cmd === 'resources') {
        console.log(chalk.cyan('\nAvailable Resources:'));
        for (const r of allResources) {
          console.log(`  ${chalk.bold(r.uri)} ${chalk.gray(`[${resourceServerMap.get(r.uri)}]`)}`);
          if (r.description) console.log(`    ${chalk.gray(r.description)}`);
        }
        if (allResources.length === 0) console.log(chalk.gray('  No resources available'));
        console.log('');
        continue;
      }
      if (cmd === 'tools') {
        console.log(chalk.cyan('\nAvailable Tools:'));
        for (const t of tools) {
          console.log(`  ${chalk.bold(t.name)}`);
          if (t.description) console.log(`    ${chalk.gray(t.description)}`);
        }
        console.log('');
        continue;
      }
      if (cmd === 'logout') {
        console.log(chalk.yellow('\nOpening IDP logout page...'));
        await open(`${config.idpUrl}/session/end`);
        console.log(chalk.gray('Session ended. Restart CLI to re-authenticate.\n'));
        continue;
      }
      console.log(chalk.red('Unknown command. Try /servers, /resources, /tools, /clear, /logout, or /quit\n'));
      continue;
    }

    const historyLengthBefore = conversationHistory.length;
    conversationHistory.push({ role: 'user', content: userInput });

    const spinner = ora({ text: 'Thinking...', color: 'cyan', stream: process.stderr }).start();

    try {
      let response = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4096,
        system: systemPrompt,
        tools,
        messages: conversationHistory,
      });

      while (response.stop_reason === 'tool_use') {
        const toolUseBlocks = response.content.filter(
          (block): block is Anthropic.ToolUseBlock => block.type === 'tool_use'
        );

        spinner.text = `Using ${toolUseBlocks.length} tool(s)...`;
        conversationHistory.push({ role: 'assistant', content: response.content });

        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const toolUse of toolUseBlocks) {
          spinner.text = `Calling ${toolUse.name}...`;
          try {
            const result = await handleToolCall(
              toolUse.name,
              toolUse.input as Record<string, unknown>
            );
            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: result,
            });
          } catch (toolError) {
            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: `Error: ${toolError instanceof Error ? toolError.message : 'Unknown error'}`,
              is_error: true,
            });
          }
        }

        conversationHistory.push({ role: 'user', content: toolResults });

        spinner.text = 'Processing results...';
        response = await anthropic.messages.create({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 4096,
          system: systemPrompt,
          tools,
          messages: conversationHistory,
        });
      }

      spinner.stop();
      conversationHistory.push({ role: 'assistant', content: response.content });

      const textContent = response.content.find(
        (block): block is Anthropic.TextBlock => block.type === 'text'
      );

      if (textContent) {
        console.log(chalk.green('Claude: ') + textContent.text + '\n');
      } else {
        console.log(chalk.yellow('Claude: [No text response]\n'));
      }
    } catch (error) {
      spinner.fail('Error');
      if (error instanceof Error) {
        console.error(chalk.red(`Error: ${error.message}`));
      } else {
        console.error(chalk.red(`Error: ${JSON.stringify(error)}`));
      }
      console.log('');

      while (conversationHistory.length > historyLengthBefore) {
        conversationHistory.pop();
      }
    }
  }

  rl.close();

  // Close all connections
  for (const server of connectedServers.values()) {
    await server.client.close();
  }
}

// Main
async function main() {
  console.log(chalk.bold.magenta('\n  MCP Interactive CLI with Claude AI'));
  console.log(chalk.bold.magenta('  Multi-Server Cross-App Access (XAA)\n'));

  if (!config.anthropicApiKey) {
    console.error(chalk.red('Error: ANTHROPIC_API_KEY not set in .env file'));
    process.exit(1);
  }

  if (mcpServers.length === 0) {
    console.error(chalk.red('Error: No MCP servers configured'));
    process.exit(1);
  }

  console.log(chalk.gray(`Configured ${mcpServers.length} MCP server(s):`));
  for (const server of mcpServers) {
    console.log(chalk.gray(`  - ${server.name}: ${server.url}`));
  }

  const anthropic = new Anthropic({ apiKey: config.anthropicApiKey });

  // Step 1: Authenticate once with IDP - keep ID token
  idToken = await authenticate();

  // Step 2: Discover capabilities (may connect temporarily, then disconnect)
  await discoverServerCapabilities();

  console.log(chalk.green('\n✔ Ready - all servers connected'));

  // Step 3: Start chat - connections happen on demand
  await runInteractiveChat(anthropic);
}

main().catch((error) => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});
