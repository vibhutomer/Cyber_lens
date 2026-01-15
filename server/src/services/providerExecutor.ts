import type {
  IocType,
  ThreatIntelProvider,
} from "../constants/provider.interface";
import { OTXProvider } from "../constants/otx.provider";
import { AbuseIPDBProvider } from "../constants/abuseipdb.provider";
import { VirusTotalProvider } from "../constants/virustotal.provider";

const DEFAULT_TIMEOUT_MS = 4000;

export const ALL_PROVIDERS: ReadonlyArray<ThreatIntelProvider> = [
  new OTXProvider(),
  new AbuseIPDBProvider(),
  new VirusTotalProvider(),
];

export type ProviderExecutionStatus = "success" | "timeout" | "error";

export interface ProviderExecutionResult<T = unknown> {
  provider: string;
  status: ProviderExecutionStatus;
  data?: T;
  error?: string;
}

export interface ProviderExecutorOptions<TOptions = Record<string, unknown>> {
  //timeout window
  timeoutMs?: number;
  providerOptions?: TOptions;
}

const isTimeoutError = (error: unknown): error is Error =>
  error instanceof Error && error.name === "TimeoutError";

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const timeoutError = new Error("Provider execution timed out");
      timeoutError.name = "TimeoutError";
      reject(timeoutError);
    }, timeoutMs);

    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

export async function executeProviders<
  TResponse = unknown,
  TOptions = Record<string, unknown>,
>(
  providers: ReadonlyArray<ThreatIntelProvider<TResponse, TOptions>>,
  ioc: string,
  type: IocType,
  options: ProviderExecutorOptions<TOptions> = {},
): Promise<ProviderExecutionResult<TResponse>[]> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const eligibleProviders = providers.filter((provider) =>
    provider.supportedIocTypes.includes(type),
  );

  const executions = eligibleProviders.map((provider) => ({
    provider,
    execution: withTimeout(
      provider.query(ioc, type, options.providerOptions),
      timeoutMs,
    ),
  }));

  const settled = await Promise.allSettled(
    executions.map(({ execution }) => execution),
  );

  return settled.map((result, index) => {
    const { provider } = executions[index]!;

    if (result.status === "fulfilled") {
      return {
        provider: provider.name,
        status: "success" as const,
        data: result.value,
      };
    }

    if (isTimeoutError(result.reason)) {
      return {
        provider: provider.name,
        status: "timeout" as const,
        error: result.reason.message,
      };
    }

    return {
      provider: provider.name,
      status: "error" as const,
      error:
        result.reason instanceof Error
          ? result.reason.message
          : String(result.reason),
    };
  });
}
