// Talking to Jev: one transport (TypeSafe over HTTPS, a relay, or an offline stand-in), retries, a
// concurrency limit and a cache keyed by the SHA-256 of the exact request body, so a replay of the same
// request returns the same answer without a call. Runs in Node and in a browser; files.ts keeps the
// cache in a file.
import {sha256} from './hash.ts';

export const API = 'https://api.typesafe.ai/v1/systemone';
export const MODEL = 'jev-1.13.0';

export interface JevAnswer { type: string; noul?: number; choice?: string; probabilities?: Record<string, number>; confidence?: number }
export interface JevResponse { model?: string; answers: Record<string, JevAnswer>; usage?: {input_tokens?: number; output_tokens?: number} }

/** Sends one request body and returns the parsed response; throws TransportError on failure. */
export type Transport = (body: string, signal?: AbortSignal) => Promise<JevResponse>;

export class TransportError extends Error {
  readonly retryable: boolean;
  readonly retryAfter: number | null;
  constructor(message: string, retryable: boolean, retryAfter: number | null = null) {
    super(message);
    this.retryable = retryable;
    this.retryAfter = retryAfter;
  }
}

export {sha256};

/** TypeSafe's API. 429, 529, 5xx, timeouts and network errors are retryable; other 4xx are not. */
export function typesafe(key: string, {endpoint = API, timeoutMs = 120_000} = {}): Transport {
  return async (body, signal) => {
    let response: Response;
    try {
      response = await fetch(endpoint, {method: 'POST', body, headers: {'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json'},
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)});
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new TransportError(`TypeSafe unreachable or timed out (${(error as Error).name})`, true);
    }
    const text = await response.text();
    if (!response.ok) {
      const status = response.status;
      const after = Number(response.headers.get('retry-after'));
      const retryable = status === 429 || status >= 500;
      const hint = status === 401 || status === 403 ? '; check TYPESAFE_API_KEY' : status === 422 ? `: ${text.slice(0, 300)}` : '';
      throw new TransportError(`TypeSafe returned HTTP ${status}${hint}`, retryable, Number.isFinite(after) && after > 0 ? after * 1000 : null);
    }
    try {
      return JSON.parse(text) as JevResponse;
    } catch {
      throw new TransportError('TypeSafe returned a response that is not JSON', false);
    }
  };
}

export interface CallRecord {
  sha256: string; cached: boolean; attempts: number; ms: number; bytes: number; questions: number;
  model?: string; input_tokens?: number; output_tokens?: number; error?: string;
}

/** Where answers are kept between runs (files.ts answerFile, or a browser's memory). */
export interface AnswerStore {
  load(): Iterable<[string, JevResponse]>;
  save(sha256: string, response: JevResponse): void;
}

export interface ClientOptions {
  concurrency?: number;
  retries?: number;
  backoffMs?: (attempt: number) => number;
  /** Earlier answers, reused for identical requests; new answers are saved there. */
  answers?: AnswerStore;
  /** Receives every distinct request body, whether sent or answered from the cache (files.ts requestLog). */
  onRequest?: (sha256: string, body: string) => void;
  sleep?: (ms: number) => Promise<void>;
}

const encoder = new TextEncoder();
const bytes = (text: string) => encoder.encode(text).length;

/** Calls Jev through a transport with retries, a concurrency limit and an answer cache. */
export class JevClient {
  readonly calls: CallRecord[] = [];
  private readonly cache = new Map<string, JevResponse>();
  private active = 0;
  private readonly queue: (() => void)[] = [];
  private readonly transport: Transport;
  private readonly options: Required<Omit<ClientOptions, 'answers' | 'onRequest'>> & Pick<ClientOptions, 'answers' | 'onRequest'>;
  private readonly logged = new Set<string>();

  constructor(transport: Transport, options: ClientOptions = {}) {
    this.transport = transport;
    this.options = {concurrency: 8, retries: 5, backoffMs: attempt => Math.min(30_000, 1000 * 2 ** (attempt - 1)),
      sleep: ms => new Promise(resolve => setTimeout(resolve, ms)), ...options};
    for (const [digest, response] of options.answers?.load() ?? []) this.cache.set(digest, response);
  }

  get cachedAnswers(): number { return this.cache.size; }

  async ask(body: string, questions: number, signal?: AbortSignal): Promise<JevResponse> {
    const digest = sha256(body);
    if (this.options.onRequest && !this.logged.has(digest)) {
      this.logged.add(digest);
      this.options.onRequest(digest, body);
    }
    const hit = this.cache.get(digest);
    if (hit) {
      this.calls.push({sha256: digest, cached: true, attempts: 0, ms: 0, bytes: body.length, questions});
      return hit;
    }
    await this.slot();
    const started = performance.now();
    let attempt = 0;
    try {
      for (;;) {
        attempt++;
        try {
          const response = await this.transport(body, signal);
          if (!response || typeof response.answers !== 'object') throw new TransportError('Jev response has no answers', false);
          this.cache.set(digest, response);
          this.options.answers?.save(digest, response);
          this.calls.push({sha256: digest, cached: false, attempts: attempt, ms: performance.now() - started, bytes: bytes(body),
            questions, model: response.model, input_tokens: response.usage?.input_tokens, output_tokens: response.usage?.output_tokens});
          return response;
        } catch (error) {
          const retryable = error instanceof TransportError && error.retryable && attempt <= this.options.retries && !signal?.aborted;
          if (!retryable) {
            this.calls.push({sha256: digest, cached: false, attempts: attempt, ms: performance.now() - started, bytes: bytes(body),
              questions, error: (error as Error).message});
            throw error;
          }
          await this.options.sleep((error as TransportError).retryAfter ?? this.options.backoffMs(attempt));
        }
      }
    } finally {
      this.release();
    }
  }

  private slot(): Promise<void> {
    if (this.active < this.options.concurrency) { this.active++; return Promise.resolve(); }
    return new Promise(resolve => this.queue.push(() => { this.active++; resolve(); }));
  }

  private release() {
    this.active--;
    this.queue.shift()?.();
  }
}
