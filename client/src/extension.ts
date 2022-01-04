import { workspace, ExtensionContext } from 'vscode';

import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: ExtensionContext) {

  const conf = workspace.getConfiguration('suricata-ls', null);
  const serverPath = conf.get<string>('serverPath') || 'suricata-language-server';
  const suricataPath = conf.get<string>('suricataPath') || 'suricata';

  let args_server = [];
  args_server.push(`--suricata-binary=${suricataPath}`)

  let serverOptions: ServerOptions = {
    run: {
        command: serverPath,
        args: args_server
    },
    debug: {
        command: serverPath,
        args: args_server
    }
  };

  // Options to control the language client
  let clientOptions: LanguageClientOptions = {
    // Register the server for plain text documents
    documentSelector: [{ scheme: 'file', language: 'suricata' }],
  };

  // Create the language client and start the client.
  client = new LanguageClient(
    'suricata-ls',
    'Suricata Language Server',
    serverOptions,
    clientOptions
  );

  // Start the client. This will also launch the server
  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
