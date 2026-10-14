<script lang="ts">
  /// A coloured initial for an item.
  ///
  /// Every row looked identical as plain text, so the list could only be read,
  /// never scanned. A stable shape and colour per item means you find GitHub
  /// by where it is and what colour it is, long before you read the word.
  ///
  /// ## Why not favicons
  ///
  /// The obvious upgrade is the real site icon, and several managers do it.
  /// Fetching one tells whoever serves it that this vault holds an entry for
  /// that site — a request per saved login, from the user's own IP, to a third
  /// party. That is the vault's contents leaking by another name, so it is out
  /// regardless of how much better it would look.
  import type { ItemKind } from "./types";

  let { title, kind, size = 30 }:
    { title: string; kind: ItemKind; size?: number } = $props();

  /// FNV-1a. Any stable hash would do; this one is four lines and has no
  /// clustering on the short, similar strings that domain names tend to be.
  function hash(text: string): number {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }

  /// Skip the scheme and any www., so github.com and https://github.com/login
  /// land on the same colour and letter.
  const seed = $derived(
    title.replace(/^[a-z]+:\/\//i, "").replace(/^www\./i, "").toLowerCase(),
  );

  const letter = $derived((seed.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase());

  /// Eight steps of grey rather than a hue.
  ///
  /// Colour made the list scannable but it was the only colour in the app, and
  /// a wall of tinted squares reads as decoration. Lightness distinguishes
  /// items nearly as well at a glance and keeps the whole interface two-tone.
  ///
  /// Golden-ratio stepping still, so adjacent hashes land far apart and
  /// neighbouring rows rarely share a shade.
  const step = $derived(Math.floor(((hash(seed) * 0.618033988749895) % 1) * 8));

  const FALLBACK: Record<ItemKind, string> = {
    login: "Login",
    note: "Note",
    card: "Card",
    apikey: "API key",
    env: "Secret",
    passkey: "Passkey",
  };
</script>

<span
  class="avatar"
  style="--step:{step}; --size:{size}px"
  aria-label={FALLBACK[kind]}
  title={FALLBACK[kind]}>
  {letter}
</span>

<style>
  .avatar {
    flex-shrink: 0;
    width: var(--size);
    height: var(--size);
    display: grid;
    place-items: center;
    border-radius: calc(var(--size) * 0.3);
    font-size: calc(var(--size) * 0.42);
    font-weight: 600;
    line-height: 1;
    user-select: none;
    /* The step spreads the ground across a narrow band and the letter across
       a wider one, so even neighbouring shades stay apart without any of them
       becoming bright enough to pull the eye on its own. */
    color: hsl(0 0% calc(56% + var(--step) * 4%));
    background: hsl(0 0% calc(13% + var(--step) * 1.6%));
    box-shadow: inset 0 0 0 1px hsl(0 0% calc(22% + var(--step) * 1.8%));
  }

  @media (prefers-color-scheme: light) {
    .avatar {
      color: hsl(0 0% calc(44% - var(--step) * 3.5%));
      background: hsl(0 0% calc(95% - var(--step) * 1.4%));
      box-shadow: inset 0 0 0 1px hsl(0 0% calc(86% - var(--step) * 1.6%));
    }
  }
</style>
