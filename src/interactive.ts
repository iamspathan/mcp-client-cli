#!/usr/bin/env node
/**
 * Interactive MCP Client with Claude AI
 *
 * An AI-powered CLI that uses Claude to interact with MCP servers.
 * Claude can read resources, call tools, and have conversations about the data.
 */

import Anthropic from '@anthropic-ai/sdk';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  applyMiddlewares,
  withCrossAppAccess,
} from '@modelcontextprotocol/client';
import express from 'express';
import open from 'open';
import crypto from 'node:crypto';
import readline from 'node:readline';
import dotenv from 'dotenv';
import chalk from 'chalk';
import ora from 'ora';

dotenv.config();

// Configuration
const config = {
  idpUrl: process.env.IDP_URL || 'http://localhost:4000',
  authServerUrl: process.env.AUTH_SERVER_URL || 'http://localhost:5001',
  mcpServerUrl: process.env.MCP_SERVER_URL || 'http://localhost:5002',
  clientId: process.env.CLIENT_ID || 'mcp-tester',
  clientSecret: process.env.CLIENT_SECRET || 'secret-mcp-tester',
  callbackPort: parseInt(process.env.CALLBACK_PORT || '3333', 10),
  mcpAudience: process.env.MCP_AUDIENCE || 'http://localhost:5002/mcp',
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
};

const REDIRECT_URI = `http://localhost:${config.callbackPort}/callback`;

// Types
interface McpTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

interface McpResource {
  uri: string;
  name: string;
  description?: string;
}

// PKCE helpers
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Decode JWT
function decodeJwt(token: string): Record<string, unknown> {
  try {
    const parts = token.split('.');
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    return { error: 'Failed to decode' };
  }
}

// OAuth flow
async function authenticate(): Promise<string> {
  const spinner = ora('Starting authentication...').start();

  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  let resolveAuthCode: (code: string) => void;
  const authCodePromise = new Promise<string>((resolve) => {
    resolveAuthCode = resolve;
  });

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
    resolveAuthCode(code);
  });

  const server = app.listen(config.callbackPort);

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

  const authUrl = `${config.idpUrl}/authorize?${params.toString()}`;
  spinner.text = 'Opening browser for login...';
  await open(authUrl);

  spinner.text = 'Waiting for authentication...';
  const code = await authCodePromise;
  server.close();

  spinner.text = 'Exchanging code for tokens...';
  const tokenResponse = await fetch(`${config.idpUrl}/token`, {
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

  if (!tokenResponse.ok) {
    throw new Error(`Token exchange failed: ${await tokenResponse.text()}`);
  }

  const tokens = await tokenResponse.json() as { id_token: string; access_token?: string };
  const userInfo = decodeJwt(tokens.id_token);
  spinner.succeed(`Authenticated as ${chalk.cyan(userInfo.email || userInfo.sub)}`);

  return tokens.id_token;
}

// Connect to MCP with SDK middleware
async function connectToMcp(idToken: string): Promise<Client> {
  const spinner = ora('Connecting to MCP server...').start();

  const xaaMiddleware = withCrossAppAccess({
    idpUrl: config.idpUrl,
    idToken,
    idpClientId: config.clientId,
    idpClientSecret: config.clientSecret,
    mcpAuthorisationServerUrl: config.authServerUrl,
    mcpResourceUrl: config.mcpAudience,
    mcpClientId: config.clientId,
    mcpClientSecret: config.clientSecret,
    scope: ['todos.read', 'mcp.access'],
  });

  const enhancedFetch = applyMiddlewares(xaaMiddleware)(fetch);

  const transport = new StreamableHTTPClientTransport(
    new URL(`${config.mcpServerUrl}/mcp`),
    { fetch: enhancedFetch }
  );

  const client = new Client(
    { name: 'mcp-interactive-cli', version: '1.0.0' },
    { capabilities: {} }
  );

  await client.connect(transport);

  // Try to get server info (may be undefined due to SDK version)
  const serverInfo = client.getServerVersion();
  if (serverInfo?.name) {
    spinner.succeed(`Connected to ${chalk.cyan(serverInfo.name)} v${serverInfo.version ?? '?'}`);
  } else {
    // Fallback: just show connected
    spinner.succeed('Connected to MCP server');
  }

  // Show XAA flow completion
  console.log(chalk.green('✔ Enterprise Managed Authorization (Cross-App Access) flow complete'));

  return client;
}

// Convert MCP tools to Claude tools format
function mcpToolsToClaudeTools(tools: McpTool[]): Anthropic.Tool[] {
  return tools.map((tool) => ({
    name: tool.name,
    description: tool.description || `MCP tool: ${tool.name}`,
    input_schema: tool.inputSchema as Anthropic.Tool['input_schema'],
  }));
}

// Create resource reading tools for Claude
function createResourceTools(resources: McpResource[]): Anthropic.Tool[] {
  return [
    {
      name: 'list_resources',
      description: 'List all available MCP resources',
      input_schema: {
        type: 'object' as const,
        properties: {},
        required: [],
      },
    },
    {
      name: 'read_resource',
      description: `Read content from an MCP resource. Available resources: ${resources.map((r) => r.uri).join(', ')}`,
      input_schema: {
        type: 'object' as const,
        properties: {
          uri: {
            type: 'string',
            description: 'The URI of the resource to read',
            enum: resources.map((r) => r.uri),
          },
        },
        required: ['uri'],
      },
    },
  ];
}

// Handle tool calls from Claude
async function handleToolCall(
  client: Client,
  resources: McpResource[],
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  try {
    if (toolName === 'list_resources') {
      return JSON.stringify(
        resources.map((r) => ({
          uri: r.uri,
          name: r.name,
          description: r.description,
        })),
        null,
        2
      );
    }

    if (toolName === 'read_resource') {
      const uri = toolInput.uri as string;
      const result = await client.readResource({ uri });
      const contents = result.contents.map((c) => {
        if ('text' in c) return c.text;
        if ('blob' in c) return `[Binary data: ${c.mimeType}]`;
        return '[Unknown content]';
      });
      return contents.join('\n');
    }

    // Handle MCP tools
    const result = await client.callTool({ name: toolName, arguments: toolInput });
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
async function runInteractiveChat(
  anthropic: Anthropic,
  mcpClient: Client,
  tools: Anthropic.Tool[],
  resources: McpResource[]
) {
  const conversationHistory: Anthropic.MessageParam[] = [];

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  // Prompt helper that ensures stdin stays active
  const prompt = (query: string): Promise<string> =>
    new Promise((resolve) => {
      // Resume stdin to ensure event loop stays alive (fixes issue with ora spinner)
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
  console.log(chalk.gray('Commands: /resources, /tools, /clear, /logout, /quit\n'));

  const systemPrompt = `You are a helpful assistant that can interact with an MCP (Model Context Protocol) server.
You have access to tools that let you read resources from the server.

Available resources:
${resources.map((r) => `- ${r.uri}: ${r.description || r.name}`).join('\n')}

When users ask about their data, use the read_resource tool to fetch the information.
Be concise and helpful in your responses. Format data nicely when presenting it.`;

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
      if (cmd === 'resources') {
        console.log(chalk.cyan('\nAvailable Resources:'));
        for (const r of resources) {
          console.log(`  ${chalk.bold(r.uri)}`);
          if (r.description) console.log(`    ${chalk.gray(r.description)}`);
        }
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
      console.log(chalk.red('Unknown command. Try /resources, /tools, /clear, /logout, or /quit\n'));
      continue;
    }

    // Track history length before this turn
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

      // Handle tool use loop
      while (response.stop_reason === 'tool_use') {
        const toolUseBlocks = response.content.filter(
          (block): block is Anthropic.ToolUseBlock => block.type === 'tool_use'
        );

        spinner.text = `Using ${toolUseBlocks.length} tool(s)...`;

        // Add assistant's tool use response to history
        conversationHistory.push({ role: 'assistant', content: response.content });

        // Execute tools and collect results
        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const toolUse of toolUseBlocks) {
          spinner.text = `Calling ${toolUse.name}...`;
          try {
            const result = await handleToolCall(
              mcpClient,
              resources,
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

        // Add tool results as user message
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

      // Add final assistant response to history
      conversationHistory.push({ role: 'assistant', content: response.content });

      // Extract and display text response
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
        if ('status' in error) {
          console.error(chalk.gray(`Status: ${(error as any).status}`));
        }
        if ('error' in error) {
          console.error(chalk.gray(`Details: ${JSON.stringify((error as any).error, null, 2)}`));
        }
      } else {
        console.error(chalk.red(`Error: ${JSON.stringify(error)}`));
      }
      console.log('');

      // Rollback to state before this turn
      while (conversationHistory.length > historyLengthBefore) {
        conversationHistory.pop();
      }
    }
  }

  rl.close();
  await mcpClient.close();
}

// Main
async function main() {
  console.log(chalk.bold.magenta('\n  MCP Interactive CLI with Claude AI\n'));

  // Check for API key
  if (!config.anthropicApiKey) {
    console.error(chalk.red('Error: ANTHROPIC_API_KEY not set in .env file'));
    console.log(chalk.gray('Add your API key to packages/mcp-client-cli/.env'));
    process.exit(1);
  }

  const anthropic = new Anthropic({ apiKey: config.anthropicApiKey });

  // Authenticate
  const idToken = await authenticate();

  // Connect to MCP
  const mcpClient = await connectToMcp(idToken);

  // Fetch available resources and tools
  const spinner = ora('Fetching MCP capabilities...').start();

  const resourcesResult = await mcpClient.listResources();
  const resources: McpResource[] = resourcesResult.resources.map((r) => ({
    uri: r.uri,
    name: r.name,
    description: r.description,
  }));

  let mcpTools: McpTool[] = [];
  try {
    const toolsResult = await mcpClient.listTools();
    mcpTools = toolsResult.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as Record<string, unknown>,
    }));
  } catch {
    // Server might not support tools
  }

  spinner.succeed(`Found ${chalk.cyan(resources.length)} resources and ${chalk.cyan(mcpTools.length)} tools`);

  // Build Claude tools
  const claudeTools: Anthropic.Tool[] = [
    ...createResourceTools(resources),
    ...mcpToolsToClaudeTools(mcpTools),
  ];

  // Start interactive chat
  await runInteractiveChat(anthropic, mcpClient, claudeTools, resources);
}

main().catch((error) => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});
