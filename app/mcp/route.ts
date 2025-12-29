import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { spawn } from "node:child_process";
import fs from "node:fs";

const pythonPath = process.env.PYTHON_BIN || "python3";
const smugglerPath = process.env.SMUGGLER_PATH || "/opt/smuggler/smuggler.py";

const handler = createMcpHandler(
  async (server) => {
    server.tool(
      "do-smuggler",
      "Run Smuggler to detect HTTP Request Smuggling vulnerabilities",
      {
        url: z.string().url().describe("Target URL to detect HTTP Request Smuggling"),
        smuggler_args: z.array(z.string()).optional().describe(`Additional smuggler arguments\n        -m, --method METHOD  Specify the HTTP method to use (default: POST)\n        -v, --vhost VHOST    Specify a virtual host to use\n        -l, --len            Enable Content-Length header in all requests\n        -c, --configfile FILE\n                             Specify a configuration file to load payloads from\n        -x                   Exit on the first finding\n        -t, --timeout TIMEOUT\n                             Socket timeout value (default: 5)\n        -verify VERIFY       Verify findings with more requests; never, quick or thorough (default: quick)`),
      },
      async ({ url, smuggler_args = [] }) => {
        if (!fs.existsSync(smugglerPath)) {
          return {
            content: [
              {
                type: "text",
                text: `Smuggler script not found at ${smugglerPath}. Ensure it is cloned during build.`,
              },
            ],
          };
        }

        const allArgs = [smugglerPath, "-u", url, ...smuggler_args];
        let output = "";

        const child = spawn(pythonPath, allArgs);

        child.stdout.on("data", (data) => {
          output += data.toString();
        });

        child.stderr.on("data", (data) => {
          output += data.toString();
        });

        const result = await new Promise<
          | { success: true; output: string }
          | { success: false; code: number | null; error?: string }
        >((resolve) => {
          child.on("close", (code) => {
            resolve({ success: code === 0, output, code });
          });

          child.on("error", (err) => {
            resolve({ success: false, code: null, error: err.message });
          });
        });

        if (!result.success) {
          return {
            content: [
              {
                type: "text",
                text: `Smuggler failed (code: ${result.code ?? "spawn error"}). ${
                  result.error || "See logs"
                }\n\n${output}`,
              },
            ],
          };
        }

        const clean = removeAnsiCodes(result.output);
        const findings = parseResults(clean);

        return {
          content: [
            {
              type: "text",
              text: clean,
            },
          ],
          metadata: {
            findings,
            command: `${pythonPath} ${allArgs.join(" ")}`,
          },
        };
      }
    );
  },
  {
    capabilities: {
      tools: {
        "do-smuggler": {
          description: "Run Smuggler to detect HTTP Request Smuggling vulnerabilities",
        },
      },
    },
  },
  {
    basePath: "",
    verboseLogs: true,
    maxDuration: 300,
    disableSse: true,
  }
);

function removeAnsiCodes(input: string): string {
  return input.replace(/\x1B\[[0-9;]*[mGK]/g, "");
}

type VulnEntry = {
  mutation: string;
  severity: string;
};

function parseResults(output: string) {
  const vulnerabilities: { cl_te: VulnEntry[]; te_cl: VulnEntry[] } = {
    cl_te: [],
    te_cl: [],
  };

  const clteRegex = /\[(\+|\!)\] Potential (CL\.TE) Vulnerability Found \((\w+)\)/gi;
  const teclRegex = /\[(\+|\!)\] Potential (TE\.CL) Vulnerability Found \((\w+)\)/gi;

  let match: RegExpExecArray | null;
  while ((match = clteRegex.exec(output)) !== null) {
    vulnerabilities.cl_te.push({
      mutation: match[3],
      severity: match[1] === "+" ? "high" : "medium",
    });
  }

  while ((match = teclRegex.exec(output)) !== null) {
    vulnerabilities.te_cl.push({
      mutation: match[3],
      severity: match[1] === "+" ? "high" : "medium",
    });
  }

  return vulnerabilities;
}

export { handler as GET, handler as POST, handler as DELETE };
