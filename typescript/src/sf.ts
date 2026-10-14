/**
 * Structured Field Values for HTTP (RFC 8941): the subset HTTP Message
 * Signatures need, parsed strictly and serialised strictly.
 *
 * Dictionaries, Items and Inner Lists; bare items of type String, Token,
 * Integer, Decimal, Byte Sequence and Boolean; parameters on items and inner
 * lists. A parse error throws `SFError`. Serialisation is the strict form of
 * section 4, which is what the signature base requires (RFC 9421 sections
 * 2.1.2 and 2.5), so a value re-serialised here is byte-identical to what
 * another conformant implementation produces. The Python implementation
 * has the same module; the two are kept in step.
 */

export class SFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SFError";
  }
}

/** A Token bare item (RFC 8941 section 3.3.4), kept apart from Strings. */
export class Token {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

/** A Decimal bare item, kept apart from Integers. */
export class Decimal {
  readonly value: number;
  constructor(value: number) {
    this.value = value;
  }
}

export type BareItem = string | Token | number | Decimal | Uint8Array | boolean;
export type Params = Map<string, BareItem>;

export interface Item {
  readonly kind: "item";
  readonly value: BareItem;
  readonly params: Params;
}

export interface InnerList {
  readonly kind: "inner-list";
  readonly items: Item[];
  readonly params: Params;
}

export type Member = Item | InnerList;

export function item(value: BareItem, params: Params = new Map()): Item {
  return { kind: "item", value, params };
}

export function innerList(items: Item[], params: Params = new Map()): InnerList {
  return { kind: "inner-list", items, params };
}

const TOKEN_START = /[A-Za-z*]/;
const TOKEN_CHARS = /[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/;
const KEY_START = /[a-z*]/;
const KEY_CHARS = /[a-z0-9_\-.*]/;
const NUMBER = /^-?(\d+)(\.\d+)?/;

class Parser {
  i = 0;
  readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  peek(): string {
    return this.i < this.s.length ? this.s[this.i]! : "";
  }
  take(): string {
    const c = this.peek();
    this.i += 1;
    return c;
  }
  skipSp(): void {
    while (this.peek() === " ") this.i += 1;
  }
  skipOws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i += 1;
  }
  done(): boolean {
    return this.i >= this.s.length;
  }
  fail(why: string): SFError {
    return new SFError(`${why} at offset ${this.i} in ${JSON.stringify(this.s)}`);
  }

  dictionary(): Map<string, Member> {
    const out = new Map<string, Member>();
    while (!this.done()) {
      const key = this.key();
      if (this.peek() === "=") {
        this.take();
        out.set(key, this.itemOrInnerList());
      } else {
        out.set(key, item(true, this.parameters()));
      }
      this.skipOws();
      if (this.done()) return out;
      if (this.take() !== ",") throw this.fail("expected ','");
      this.skipOws();
      if (this.done()) throw this.fail("trailing comma");
    }
    return out;
  }

  itemOrInnerList(): Member {
    return this.peek() === "(" ? this.innerList() : this.item();
  }

  innerList(): InnerList {
    if (this.take() !== "(") throw this.fail("expected '('");
    const items: Item[] = [];
    while (!this.done()) {
      this.skipSp();
      if (this.peek() === ")") {
        this.take();
        return innerList(items, this.parameters());
      }
      items.push(this.item());
      if (this.peek() !== " " && this.peek() !== ")") {
        throw this.fail("expected space or ')' in inner list");
      }
    }
    throw this.fail("unterminated inner list");
  }

  item(): Item {
    const value = this.bareItem();
    return item(value, this.parameters());
  }

  parameters(): Params {
    const params: Params = new Map();
    while (this.peek() === ";") {
      this.take();
      this.skipSp();
      const name = this.key();
      if (this.peek() === "=") {
        this.take();
        params.set(name, this.bareItem());
      } else {
        params.set(name, true);
      }
    }
    return params;
  }

  key(): string {
    if (!KEY_START.test(this.peek() || "\0")) throw this.fail("expected a key");
    const start = this.i;
    while (!this.done() && KEY_CHARS.test(this.peek())) this.i += 1;
    return this.s.slice(start, this.i);
  }

  bareItem(): BareItem {
    const c = this.peek();
    if (c === "") throw this.fail("expected a bare item");
    if (c === "-" || /\d/.test(c)) return this.number();
    if (c === '"') return this.string();
    if (TOKEN_START.test(c)) return this.token();
    if (c === ":") return this.byteSequence();
    if (c === "?") return this.boolean();
    throw this.fail("unexpected character");
  }

  number(): number | Decimal {
    const m = NUMBER.exec(this.s.slice(this.i));
    if (!m) throw this.fail("expected a number");
    const text = m[0];
    this.i += text.length;
    if (m[2] === undefined) {
      if (m[1]!.length > 15) throw this.fail("integer too long");
      return Number.parseInt(text, 10);
    }
    if (m[1]!.length > 12 || m[2].length - 1 > 3) throw this.fail("decimal too long");
    return new Decimal(Number.parseFloat(text));
  }

  string(): string {
    if (this.take() !== '"') throw this.fail("expected '\"'");
    let out = "";
    while (!this.done()) {
      const c = this.take();
      if (c === "\\") {
        const n = this.take();
        if (n !== '"' && n !== "\\") throw this.fail("bad escape in string");
        out += n;
      } else if (c === '"') {
        return out;
      } else {
        const code = c.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) throw this.fail("non-ASCII or control character in string");
        out += c;
      }
    }
    throw this.fail("unterminated string");
  }

  token(): Token {
    const start = this.i;
    this.i += 1;
    while (!this.done() && TOKEN_CHARS.test(this.peek())) this.i += 1;
    return new Token(this.s.slice(start, this.i));
  }

  byteSequence(): Uint8Array {
    if (this.take() !== ":") throw this.fail("expected ':'");
    const start = this.i;
    while (!this.done() && this.peek() !== ":") this.i += 1;
    if (this.done()) throw this.fail("unterminated byte sequence");
    const raw = this.s.slice(start, this.i);
    this.i += 1;
    if (!/^[A-Za-z0-9+/=]*$/.test(raw)) throw this.fail("bad base64 in byte sequence");
    try {
      return base64Decode(raw);
    } catch (error) {
      throw this.fail(`bad base64: ${String(error)}`);
    }
  }

  boolean(): boolean {
    if (this.take() !== "?") throw this.fail("expected '?'");
    const c = this.take();
    if (c === "1") return true;
    if (c === "0") return false;
    throw this.fail("bad boolean");
  }
}

/** Parse a Dictionary field value. Several field lines are combined by the
 * caller with `", "` before parsing, as RFC 8941 section 4.2 requires. */
export function parseDictionary(text: string): Map<string, Member> {
  const p = new Parser(text.replace(/^[ \t]+|[ \t]+$/g, ""));
  const out = p.dictionary();
  if (!p.done()) throw p.fail("trailing characters");
  return out;
}

export function parseItem(text: string): Item {
  const p = new Parser(text.replace(/^[ \t]+|[ \t]+$/g, ""));
  const out = p.item();
  if (!p.done()) throw p.fail("trailing characters");
  return out;
}

// -- RFC 8941 section 4.1, strict serialisation ------------------------------

export function serializeBareItem(value: BareItem): string {
  if (typeof value === "boolean") return value ? "?1" : "?0";
  if (value instanceof Token) return value.value;
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new SFError("integers must be whole");
    return String(value);
  }
  if (value instanceof Decimal) {
    const fixed = value.value.toFixed(3);
    const [whole, frac = "0"] = fixed.split(".");
    const trimmed = frac.replace(/0+$/, "") || "0";
    return `${whole}.${trimmed}`;
  }
  if (value instanceof Uint8Array) return `:${base64Encode(value)}:`;
  for (const c of value) {
    const code = c.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) {
      throw new SFError("string contains a non-ASCII or control character");
    }
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function serializeParams(params: Params): string {
  let out = "";
  for (const [name, value] of params) {
    out += value === true ? `;${name}` : `;${name}=${serializeBareItem(value)}`;
  }
  return out;
}

export function serializeItem(it: Item): string {
  return serializeBareItem(it.value) + serializeParams(it.params);
}

export function serializeInnerList(inner: InnerList): string {
  return `(${inner.items.map(serializeItem).join(" ")})${serializeParams(inner.params)}`;
}

/** A Dictionary member's value with its parameters, without the key
 * (RFC 9421 section 2.1.2). */
export function serializeMember(member: Member): string {
  return member.kind === "inner-list" ? serializeInnerList(member) : serializeItem(member);
}

export function base64Decode(text: string): Uint8Array {
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64UrlDecode(text: string): Uint8Array {
  return base64Decode(text.replace(/-/g, "+").replace(/_/g, "/"));
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
