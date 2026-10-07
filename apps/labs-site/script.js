const motion = document.querySelector('.motion-control');
const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
function pauseMotion(paused) {
  document.body.classList.toggle('motion-paused', paused);
  motion.setAttribute('aria-pressed', String(paused));
  motion.setAttribute('aria-label', paused ? 'Resume ambient motion' : 'Pause ambient motion');
  motion.textContent = paused ? '▷' : 'Ⅱ';
}
pauseMotion(preference.matches);
preference.addEventListener('change', event => pauseMotion(event.matches));
motion.addEventListener('click', () => pauseMotion(motion.getAttribute('aria-pressed') !== 'true'));
const filters = document.querySelectorAll('[data-filter]');
const projects = document.querySelectorAll('[data-category]');
filters.forEach(button => button.addEventListener('click', () => {
  filters.forEach(filter => filter.setAttribute('aria-pressed', String(filter === button)));
  let count = 0;
  projects.forEach(project => { project.hidden = button.dataset.filter !== 'all' && project.dataset.category !== button.dataset.filter; if (!project.hidden) count++; });
  document.getElementById('filter-status').textContent = `${count} ${count === 1 ? 'project' : 'projects'} shown`;
}));
