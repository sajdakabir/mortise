// Progressive enhancement: the full outline remains visible without JS,
// IntersectionObserver, or when the visitor prefers reduced motion.
const wordmark = document.querySelector('.footer-wordmark');
const motion = window.matchMedia('(prefers-reduced-motion: reduce)');

if (wordmark && !motion.matches && 'IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    if (entries.some(entry => entry.isIntersecting)) {
      wordmark.classList.add('is-drawing');
      observer.disconnect();
    }
  }, { threshold: 0.2 });

  wordmark.classList.add('is-ready');
  observer.observe(wordmark);

  // Changing the OS preference mid-animation immediately reveals the outline.
  motion.addEventListener('change', () => {
    if (motion.matches) {
      observer.disconnect();
      wordmark.classList.remove('is-ready', 'is-drawing');
    }
  });
}
