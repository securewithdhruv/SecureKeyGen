import { useEffect, useMemo, useRef, useState } from "react";
import { Blowfish } from "egoroof-blowfish";

type ThemeMode = "light" | "dark";

type KeySize = 16 | 24 | 32 | 64;
type OutputView = "hex" | "base64" | "armored";
type Tone = "emerald" | "cyan" | "amber" | "rose";

interface TraceItem {
  label: string;
  detail: string;
  preview: string;
}

interface GenerationResult {
  finalKeyHex: string;
  finalKeyBase64: string;
  fingerprint: string;
  armored: string;
  durationMs: number;
  trace: TraceItem[];
  aesIv: string;
  desIv: string;
  blowfishIv: string;
  salt: string;
  score: number;
}

const textEncoder = new TextEncoder();

const toneStyles: Record<Tone, string> = {
  emerald: "border-emerald-200 bg-emerald-50 text-emerald-800",
  cyan: "border-blue-200 bg-blue-50 text-blue-800",
  amber: "border-amber-200 bg-amber-50 text-amber-800",
  rose: "border-rose-200 bg-rose-50 text-rose-800",
};

const keyOptions: Array<{ label: string; value: KeySize }> = [
  { label: "128-bit", value: 16 },
  { label: "192-bit", value: 24 },
  { label: "256-bit", value: 32 },
  { label: "512-bit", value: 64 },
];

function getRandomBytes(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomHex(length: number) {
  return bytesToHex(getRandomBytes(length));
}

function forgePassphrase(length = 28) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}";
  const bytes = getRandomBytes(length);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string) {
  const sanitized = hex.replace(/\s+/g, "");
  const bytes = new Uint8Array(sanitized.length / 2);

  for (let index = 0; index < sanitized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(sanitized.slice(index, index + 2), 16);
  }

  return bytes;
}

function utf8ToBytes(value: string) {
  return textEncoder.encode(value);
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }

  return btoa(binary);
}

function parseFlexibleBytes(value: string) {
  const trimmed = value.trim();
  const normalized = trimmed.replace(/\s+/g, "");

  if (normalized.length > 0 && normalized.length % 2 === 0 && /^[\da-fA-F]+$/.test(normalized)) {
    return hexToBytes(normalized);
  }

  return utf8ToBytes(trimmed);
}

function concatBytes(...segments: Uint8Array[]) {
  const totalLength = segments.reduce((sum, segment) => sum + segment.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const segment of segments) {
    result.set(segment, offset);
    offset += segment.length;
  }

  return result;
}

function xorBytes(left: Uint8Array, right: Uint8Array) {
  const result = new Uint8Array(left.length);

  for (let index = 0; index < left.length; index += 1) {
    result[index] = left[index] ^ right[index % right.length];
  }

  return result;
}

function truncateMiddle(value: string, limit = 74) {
  if (value.length <= limit) {
    return value;
  }

  const edge = Math.max(14, Math.floor(limit / 2) - 3);
  return `${value.slice(0, edge)}...${value.slice(-edge)}`;
}

function formatFingerprint(value: string) {
  return value.match(/.{1,6}/g)?.join("-") ?? value;
}

function calculateEntropyBits(passphrase: string, entropySeed: string) {
  let charset = 0;

  if (/[a-z]/.test(passphrase)) charset += 26;
  if (/[A-Z]/.test(passphrase)) charset += 26;
  if (/\d/.test(passphrase)) charset += 10;
  if (/[^A-Za-z0-9]/.test(passphrase)) charset += 32;

  const passphraseBits = Math.round(passphrase.length * Math.log2(Math.max(charset, 1)));
  const seedBits = Math.round(Math.min(entropySeed.replace(/\s+/g, "").length, 48) * 3.6);

  return passphraseBits + seedBits;
}

function calculateSecurityScore(passphrase: string, iterations: number, keyLength: KeySize, extraEntropy: string) {
  let score = 0;

  score += Math.min(30, passphrase.length * 1.4);
  if (/[a-z]/.test(passphrase)) score += 6;
  if (/[A-Z]/.test(passphrase)) score += 6;
  if (/\d/.test(passphrase)) score += 6;
  if (/[^A-Za-z0-9]/.test(passphrase)) score += 10;

  score += Math.min(22, Math.log2(Math.max(iterations, 1)) * 1.2);
  score += keyLength === 64 ? 20 : keyLength === 32 ? 18 : keyLength === 24 ? 15 : 12;
  score += Math.min(10, extraEntropy.trim().length / 2);

  return Math.max(0, Math.min(100, Math.round(score)));
}

function getScoreMeta(score: number): { label: string; tone: Tone } {
  if (score >= 90) return { label: "Critical", tone: "emerald" };
  if (score >= 76) return { label: "Hardened", tone: "cyan" };
  if (score >= 60) return { label: "Elevated", tone: "amber" };
  return { label: "Needs Hardening", tone: "rose" };
}

function getHardeningLabel(iterations: number) {
  if (iterations >= 320000) return "Max stretch";
  if (iterations >= 220000) return "High stretch";
  if (iterations >= 140000) return "Balanced";
  return "Baseline";
}

function getCipherPosture(keyLength: KeySize) {
  if (keyLength >= 32) return "Enterprise";
  if (keyLength === 24) return "Compatibility";
  return "Fast deploy";
}

function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

async function sha256Bytes(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", asBufferSource(data));
  return new Uint8Array(digest);
}

async function sha512Bytes(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-512", asBufferSource(data));
  return new Uint8Array(digest);
}

async function derivePbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  length: number,
  hash: "SHA-256" | "SHA-512" = "SHA-512"
) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(utf8ToBytes(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: asBufferSource(salt),
      iterations,
      hash,
    },
    baseKey,
    length * 8
  );

  return new Uint8Array(bits);
}

async function aesGcmEncrypt(payload: string, keyBytes: Uint8Array, iv: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", asBufferSource(keyBytes), { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    key,
    asBufferSource(utf8ToBytes(payload))
  );
  return new Uint8Array(encrypted);
}

async function loadCryptoJs() {
  const cryptoJsModule = (await import("crypto-js")) as any;
  return cryptoJsModule.default ?? cryptoJsModule;
}

async function copyTextToClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const element = document.createElement("textarea");
  element.value = value;
  element.setAttribute("readonly", "true");
  element.style.position = "absolute";
  element.style.left = "-9999px";
  document.body.appendChild(element);
  element.select();
  document.execCommand("copy");
  document.body.removeChild(element);
}

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function MetricCard({
  label,
  value,
  hint,
  tone,
  theme,
}: {
  label: string;
  value: string;
  hint: string;
  tone: Tone;
  theme: ThemeMode;
}) {
  return (
    <div className={`rounded-xl border p-5 shadow-sm transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900 shadow-black/20" : "border-zinc-200 bg-white"}`}>
      <div className="mb-3 flex items-center justify-between">
        <p className={`text-xs font-medium uppercase tracking-wider ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>{label}</p>
        <span className={`rounded-md border px-2 py-0.5 text-[11px] font-medium ${toneStyles[tone]}`}>{hint}</span>
      </div>
      <p className={`text-xl font-semibold ${theme === "dark" ? "text-zinc-50" : "text-zinc-900"}`}>{value}</p>
    </div>
  );
}

function TraceRow({ item, theme }: { item: TraceItem; theme: ThemeMode }) {
  return (
    <div className={`rounded-xl border p-4 transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900" : "border-zinc-100 bg-zinc-50"}`}>
      <div className="mb-2">
        <p className={`text-sm font-medium ${theme === "dark" ? "text-zinc-100" : "text-zinc-900"}`}>{item.label}</p>
        <p className={`text-xs ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>{item.detail}</p>
      </div>
      <p className={`break-all font-mono text-xs leading-5 ${theme === "dark" ? "text-zinc-300" : "text-zinc-600"}`}>{item.preview}</p>
    </div>
  );
}

export function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    if (typeof window === "undefined") return "light";
    const stored = window.localStorage.getItem("securekeygen-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [passphrase, setPassphrase] = useState("ZeroTrust#Quantum@2026!");
  const [context, setContext] = useState("vault/prod/customer-secrets");
  const [salt, setSalt] = useState(() => randomHex(16));
  const [extraEntropy, setExtraEntropy] = useState(() => randomHex(12));
  const [iterations, setIterations] = useState(280000);
  const [keyLength, setKeyLength] = useState<KeySize>(32);
  const [outputView, setOutputView] = useState<OutputView>("hex");
  const [result, setResult] = useState<GenerationResult | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const autoGenerated = useRef(false);

  const securityScore = useMemo(
    () => calculateSecurityScore(passphrase, iterations, keyLength, extraEntropy),
    [extraEntropy, iterations, keyLength, passphrase]
  );
  const entropyBits = useMemo(() => calculateEntropyBits(passphrase, extraEntropy), [extraEntropy, passphrase]);
  const scoreMeta = useMemo(() => getScoreMeta(securityScore), [securityScore]);
  const hardeningLabel = useMemo(() => getHardeningLabel(iterations), [iterations]);
  const cipherPosture = useMemo(() => getCipherPosture(keyLength), [keyLength]);

  const outputValue = useMemo(() => {
    if (!result) return "";
    if (outputView === "hex") return result.finalKeyHex;
    if (outputView === "base64") return result.finalKeyBase64;
    return result.armored;
  }, [outputView, result]);

  async function handleCopy(label: string, value: string) {
    try {
      await copyTextToClipboard(value);
      setCopiedField(label);
      window.setTimeout(() => {
        setCopiedField((current) => (current === label ? null : current));
      }, 1500);
    } catch (copyError) {
      setError(copyError instanceof Error ? copyError.message : "Copy failed.");
    }
  }

  async function handleGenerate() {
    if (!passphrase.trim()) {
      setError("Master passphrase is required.");
      return;
    }

    if (!context.trim()) {
      setError("Security context is required.");
      return;
    }

    const preparedSalt = salt.trim() || randomHex(16);
    const preparedEntropy = extraEntropy.trim() || randomHex(12);
    const computedScore = calculateSecurityScore(passphrase, iterations, keyLength, preparedEntropy);

    if (!salt.trim()) setSalt(preparedSalt);
    if (!extraEntropy.trim()) setExtraEntropy(preparedEntropy);

    setError(null);
    setIsGenerating(true);

    try {
      const startedAt = performance.now();
      const saltBytes = parseFlexibleBytes(preparedSalt);
      const entropyBytes = parseFlexibleBytes(preparedEntropy);
      const normalizedContext = `${context.trim()}|salt:${preparedSalt}|entropy:${preparedEntropy}`;

      const rootMaterial = await derivePbkdf2(
        `${passphrase}::${normalizedContext}`,
        saltBytes,
        iterations,
        160,
        "SHA-512"
      );

      const preKey = rootMaterial.slice(0, keyLength);
      const xorMask = rootMaterial.slice(32, 32 + keyLength);
      const aesKey = rootMaterial.slice(64, 96);
      const desKey = rootMaterial.slice(96, 120);
      const blowfishKey = rootMaterial.slice(120, 152);
      const blowfishIv = rootMaterial.slice(152, 160);
      const xorMixed = xorBytes(preKey, xorMask);

      const aesIvSeed = await sha256Bytes(concatBytes(rootMaterial.slice(20, 52), entropyBytes, saltBytes));
      const aesIv = aesIvSeed.slice(0, 12);
      const payload = JSON.stringify({
        context: context.trim(),
        salt: bytesToHex(saltBytes),
        entropy: bytesToHex(entropyBytes),
        iterations,
        outputBits: keyLength * 8,
        xorSeed: bytesToHex(xorMixed),
      });
      const aesCipherBytes = await aesGcmEncrypt(payload, aesKey, aesIv);

      const CryptoJS = await loadCryptoJs();
      const desIvSeed = await sha256Bytes(concatBytes(rootMaterial.slice(44, 76), saltBytes, entropyBytes));
      const desIv = desIvSeed.slice(0, 8);
      const tripleDesCipher = CryptoJS.TripleDES.encrypt(
        bytesToBase64(aesCipherBytes),
        CryptoJS.enc.Hex.parse(bytesToHex(desKey)),
        {
          iv: CryptoJS.enc.Hex.parse(bytesToHex(desIv)),
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );
      const tripleDesHex = tripleDesCipher.ciphertext.toString(CryptoJS.enc.Hex);

      const blowfish = new Blowfish(blowfishKey, Blowfish.MODE.CBC, Blowfish.PADDING.PKCS5);
      blowfish.setIv(blowfishIv);
      const blowfishBytes = blowfish.encode(tripleDesHex);

      const layeredDigest = await sha512Bytes(
        concatBytes(xorMixed, aesCipherBytes, desIv, blowfishIv, blowfishBytes, saltBytes)
      );
      const postMix = xorBytes(preKey, layeredDigest.slice(0, keyLength));
      const compressionSalt = await sha256Bytes(
        concatBytes(
          saltBytes,
          aesIv,
          desIv,
          blowfishIv,
          blowfishBytes.slice(0, Math.min(48, blowfishBytes.length))
        )
      );
      const finalKeyBytes = await derivePbkdf2(
        bytesToHex(postMix),
        compressionSalt,
        Math.max(20000, Math.floor(iterations / 6)),
        keyLength,
        "SHA-256"
      );

      const finalKeyHex = bytesToHex(finalKeyBytes);
      const finalKeyBase64 = bytesToBase64(finalKeyBytes);
      const fingerprint = formatFingerprint(
        bytesToHex((await sha256Bytes(concatBytes(finalKeyBytes, saltBytes, utf8ToBytes(context.trim())))).slice(0, 12))
      );
      const durationMs = performance.now() - startedAt;

      const trace: TraceItem[] = [
        {
          label: "PBKDF2 Root",
          detail: `160-byte SHA-512 derivation @ ${iterations.toLocaleString()} rounds`,
          preview: truncateMiddle(bytesToHex(rootMaterial)),
        },
        {
          label: "XOR Mixer",
          detail: `${keyLength * 8}-bit entropy fusion over derived fragments`,
          preview: truncateMiddle(bytesToHex(xorMixed)),
        },
        {
          label: "AES-GCM Capsule",
          detail: "Authenticated encryption of the normalized key payload",
          preview: truncateMiddle(bytesToBase64(aesCipherBytes)),
        },
        {
          label: "3DES-CBC Transform",
          detail: "Secondary compatibility layer over the AES capsule",
          preview: truncateMiddle(tripleDesHex),
        },
        {
          label: "Blowfish Envelope",
          detail: "CBC wrap over the transformed stream before final compression",
          preview: truncateMiddle(bytesToHex(blowfishBytes)),
        },
        {
          label: "Final Compression",
          detail: `PBKDF2-SHA-256 squeeze to ${keyLength * 8}-bit export output`,
          preview: truncateMiddle(finalKeyHex),
        },
      ];

      const armored = JSON.stringify(
        {
          product: "SecureKeyGen",
          version: "1.0",
          fingerprint,
          generatedAt: new Date().toISOString(),
          securityContext: context.trim(),
          iterations,
          outputBits: keyLength * 8,
          securityScore: computedScore,
          salt: bytesToHex(saltBytes),
          entropy: bytesToHex(entropyBytes),
          iv: {
            aesGcm: bytesToHex(aesIv),
            tripleDes: bytesToHex(desIv),
            blowfish: bytesToHex(blowfishIv),
          },
          formats: {
            hex: finalKeyHex,
            base64: finalKeyBase64,
          },
          pipeline: trace,
          note: "Client-side key generation only. Preserve passphrase, salt, and context if reproducibility is required.",
        },
        null,
        2
      );

      setResult({
        finalKeyHex,
        finalKeyBase64,
        fingerprint,
        armored,
        durationMs,
        trace,
        aesIv: bytesToHex(aesIv),
        desIv: bytesToHex(desIv),
        blowfishIv: bytesToHex(blowfishIv),
        salt: bytesToHex(saltBytes),
        score: computedScore,
      });
    } catch (generationError) {
      setError(generationError instanceof Error ? generationError.message : "Key generation failed.");
    } finally {
      setIsGenerating(false);
    }
  }

  useEffect(() => {
    if (autoGenerated.current) return;
    autoGenerated.current = true;
    void handleGenerate();
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("securekeygen-theme", theme);
  }, [theme]);

  return (
    <div className={`min-h-screen py-12 px-4 font-sans transition-colors sm:px-6 ${theme === "dark" ? "bg-zinc-950 text-zinc-100" : "bg-zinc-50 text-zinc-900"}`}>
      <main className="mx-auto max-w-5xl space-y-8">
        
        {/* Header */}
        <header className="space-y-3">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <svg className={`h-7 w-7 ${theme === "dark" ? "text-zinc-100" : "text-zinc-800"}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4.97-3.05 7.92-7 9-3.95-1.08-7-4.03-7-9V7l7-4z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12.5l1.7 1.7 3.3-4.2" />
                </svg>
                <h1 className={`text-3xl font-bold tracking-tight ${theme === "dark" ? "text-zinc-50" : "text-zinc-900"}`}>SecureKeyGen</h1>
              </div>
              <p className={`max-w-2xl text-sm leading-relaxed ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>
                Minimal, robust client-side cryptographic key generator utilizing PBKDF2 stretching, XOR operations, and multi-layered encryption (AES, 3DES, Blowfish).
              </p>
            </div>

            <button
              type="button"
              onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
              className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800" : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50"}`}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            >
              <span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
              <span className={`rounded-md px-2 py-0.5 text-xs ${theme === "dark" ? "bg-zinc-800 text-zinc-300" : "bg-zinc-100 text-zinc-600"}`}>
                {theme === "dark" ? "☀" : "☾"}
              </span>
            </button>
          </div>
        </header>

        {/* Top metrics */}
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard label="Security score" value={`${securityScore}/100`} hint={scoreMeta.label} tone={scoreMeta.tone} theme={theme} />
          <MetricCard label="Entropy" value={`~${entropyBits} bits`} hint="Complexity" tone="cyan" theme={theme} />
          <MetricCard label="PBKDF2" value={hardeningLabel} hint={`${iterations.toLocaleString()} rounds`} tone="amber" theme={theme} />
          <MetricCard label="Output size" value={`${keyLength * 8}-bit`} hint={cipherPosture} tone="emerald" theme={theme} />
        </section>

        <section className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
          {/* Controls */}
          <div className={`space-y-6 rounded-2xl border p-6 shadow-sm transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900 shadow-black/20" : "border-zinc-200 bg-white"}`}>
            <div>
              <h2 className={`text-lg font-semibold ${theme === "dark" ? "text-zinc-50" : "text-zinc-900"}`}>Configuration</h2>
              <p className={`text-sm ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>Adjust parameters for key derivation.</p>
            </div>

            <div className="space-y-5">
              <label className="block space-y-1.5">
                <div className="flex justify-between">
                  <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>Master passphrase</span>
                  <div className={`space-x-3 text-xs ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>
                    <button type="button" onClick={() => setPassphrase(forgePassphrase())} className={`transition-colors ${theme === "dark" ? "hover:text-zinc-100" : "hover:text-zinc-900"}`}>Forge</button>
                    <button type="button" onClick={() => setShowPassphrase(c => !c)} className={`transition-colors ${theme === "dark" ? "hover:text-zinc-100" : "hover:text-zinc-900"}`}>{showPassphrase ? "Hide" : "Reveal"}</button>
                  </div>
                </div>
                <input type={showPassphrase ? "text" : "password"} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="Enter passphrase" className={`w-full rounded-lg border px-3 py-2 text-sm outline-none transition-shadow ${theme === "dark" ? "border-zinc-800 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-600 focus:ring-1 focus:ring-zinc-700" : "border-zinc-300 bg-zinc-50 text-zinc-900 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500"}`} />
              </label>

              <label className="block space-y-1.5">
                <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>Security context</span>
                <input value={context} onChange={(e) => setContext(e.target.value)} placeholder="vault/prod" className={`w-full rounded-lg border px-3 py-2 text-sm outline-none transition-shadow ${theme === "dark" ? "border-zinc-800 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-600 focus:ring-1 focus:ring-zinc-700" : "border-zinc-300 bg-zinc-50 text-zinc-900 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500"}`} />
              </label>

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1.5">
                  <div className="flex justify-between">
                    <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>Salt</span>
                    <button type="button" onClick={() => setSalt(randomHex(16))} className={`text-xs transition-colors ${theme === "dark" ? "text-zinc-400 hover:text-zinc-100" : "text-zinc-500 hover:text-zinc-900"}`}>Regenerate</button>
                  </div>
                  <input value={salt} onChange={(e) => setSalt(e.target.value)} placeholder="Hex salt" className={`w-full rounded-lg border px-3 py-2 font-mono text-sm outline-none transition-shadow ${theme === "dark" ? "border-zinc-800 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-600 focus:ring-1 focus:ring-zinc-700" : "border-zinc-300 bg-zinc-50 text-zinc-900 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500"}`} />
                </label>

                <label className="block space-y-1.5">
                  <div className="flex justify-between">
                    <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>Extra entropy</span>
                    <button type="button" onClick={() => setExtraEntropy(randomHex(12))} className={`text-xs transition-colors ${theme === "dark" ? "text-zinc-400 hover:text-zinc-100" : "text-zinc-500 hover:text-zinc-900"}`}>Regenerate</button>
                  </div>
                  <input value={extraEntropy} onChange={(e) => setExtraEntropy(e.target.value)} placeholder="Hex entropy" className={`w-full rounded-lg border px-3 py-2 font-mono text-sm outline-none transition-shadow ${theme === "dark" ? "border-zinc-800 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-600 focus:ring-1 focus:ring-zinc-700" : "border-zinc-300 bg-zinc-50 text-zinc-900 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500"}`} />
                </label>
              </div>

              <div className="space-y-4 pt-2">
                <label className="block space-y-3">
                  <div className="flex justify-between">
                    <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>PBKDF2 iterations</span>
                    <span className={`rounded-md px-2 py-0.5 text-sm font-medium ${theme === "dark" ? "bg-zinc-800 text-zinc-100" : "bg-zinc-100 text-zinc-900"}`}>{iterations.toLocaleString()}</span>
                  </div>
                  <input type="range" min={80000} max={400000} step={10000} value={iterations} onChange={(e) => setIterations(Number(e.target.value))} className="w-full cursor-pointer" />
                </label>

                <div className="space-y-2">
                  <span className={`text-sm font-medium ${theme === "dark" ? "text-zinc-300" : "text-zinc-700"}`}>Output size</span>
                  <div className="flex flex-wrap gap-2">
                    {keyOptions.map((opt) => (
                      <button key={opt.value} type="button" onClick={() => setKeyLength(opt.value)} className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${keyLength === opt.value ? theme === "dark" ? "border-zinc-100 bg-zinc-100 text-zinc-900" : "border-zinc-900 bg-zinc-900 text-white" : theme === "dark" ? "border-zinc-800 bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100" : "border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900"}`}>
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              
              {error && <div className={`rounded-lg border p-3 text-sm ${theme === "dark" ? "border-red-950 bg-red-950/40 text-red-200" : "border-red-200 bg-red-50 text-red-700"}`}>{error}</div>}

              <div className="flex flex-col gap-3 pt-4 sm:flex-row">
                <button type="button" onClick={() => void handleGenerate()} disabled={isGenerating} className={`flex-1 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-70 ${theme === "dark" ? "bg-zinc-100 text-zinc-900 hover:bg-white" : "bg-zinc-900 text-white hover:bg-zinc-800"}`}>
                  {isGenerating ? "Generating..." : "Generate Key"}
                </button>
                <button type="button" onClick={() => result && downloadTextFile(`securekeygen-${result.fingerprint}.json`, result.armored)} disabled={!result} className={`sm:flex-none rounded-lg border px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${theme === "dark" ? "border-zinc-800 bg-zinc-900 text-zinc-200 hover:bg-zinc-800" : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50"}`}>
                  Export JSON
                </button>
              </div>
            </div>
          </div>

          {/* Output */}
          <div className="space-y-6">
            <div className={`flex h-full flex-col rounded-2xl border p-6 shadow-sm transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900 shadow-black/20" : "border-zinc-200 bg-white"}`}>
              <div className="mb-4 flex items-start justify-between shrink-0 gap-4">
                <div>
                  <h2 className={`text-lg font-semibold ${theme === "dark" ? "text-zinc-50" : "text-zinc-900"}`}>Generated Output</h2>
                  <p className={`mt-1 text-sm ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>Fingerprint: <span className={`rounded px-1.5 py-0.5 font-mono ${theme === "dark" ? "bg-zinc-800 text-zinc-200" : "bg-zinc-100 text-zinc-700"}`}>{result?.fingerprint ?? "---"}</span></p>
                </div>
                <div className={`flex gap-1 rounded-lg p-1 ${theme === "dark" ? "bg-zinc-950" : "bg-zinc-100"}`}>
                  {(["hex", "base64", "armored"] as OutputView[]).map((view) => (
                    <button key={view} type="button" onClick={() => setOutputView(view)} className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-colors ${outputView === view ? theme === "dark" ? "bg-zinc-800 text-zinc-50 shadow-sm" : "bg-white text-zinc-900 shadow-sm" : theme === "dark" ? "text-zinc-400 hover:text-zinc-100" : "text-zinc-500 hover:text-zinc-900"}`}>
                      {view}
                    </button>
                  ))}
                </div>
              </div>

              <div className={`relative flex min-h-[16rem] flex-1 flex-col rounded-xl border p-4 transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-950" : "border-zinc-200 bg-zinc-50"}`}>
                <button type="button" onClick={() => outputValue && void handleCopy("output", outputValue)} disabled={!outputValue} className={`absolute right-3 top-3 rounded-md border px-2.5 py-1.5 text-xs font-medium shadow-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${theme === "dark" ? "border-zinc-800 bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100" : "border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900"}`}>
                  {copiedField === "output" ? "Copied!" : "Copy"}
                </button>
                <pre className={`flex-1 overflow-auto whitespace-pre-wrap break-all pb-2 pt-8 font-mono text-sm leading-6 ${theme === "dark" ? "text-zinc-200" : "text-zinc-800"}`}>
                  {outputValue || "Ready to generate."}
                </pre>
              </div>
            </div>
          </div>
        </section>

        <section className={`rounded-2xl border p-6 shadow-sm transition-colors ${theme === "dark" ? "border-zinc-800 bg-zinc-900 shadow-black/20" : "border-zinc-200 bg-white"}`}>
          <div className="mb-6 flex items-center justify-between gap-4">
            <div>
              <h2 className={`text-lg font-semibold ${theme === "dark" ? "text-zinc-50" : "text-zinc-900"}`}>Pipeline Trace</h2>
              <p className={`mt-1 text-sm ${theme === "dark" ? "text-zinc-400" : "text-zinc-500"}`}>Layered transformation visibility and execution steps.</p>
            </div>
            {result && (
              <span className={`rounded-full px-3 py-1 text-sm font-medium ${theme === "dark" ? "bg-zinc-800 text-zinc-300" : "bg-zinc-100 text-zinc-500"}`}>
                {result.durationMs.toFixed(1)} ms
              </span>
            )}
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {result?.trace.map((item) => <TraceRow key={item.label} item={item} theme={theme} />) ?? (
              <div className={`col-span-full rounded-xl border border-dashed p-8 text-center text-sm ${theme === "dark" ? "border-zinc-700 bg-zinc-950 text-zinc-400" : "border-zinc-300 bg-zinc-50 text-zinc-500"}`}>
                Generate a key to view the end-to-end execution trace.
              </div>
            )}
          </div>
        </section>
        
        <footer className={`pb-4 text-center text-xs ${theme === "dark" ? "text-zinc-500" : "text-zinc-400"}`}>
          Client-side key generation only. Preserve passphrase, salt, and context if reproducibility is required.
        </footer>
      </main>
    </div>
  );
}
