const projects = {
  "pay": {
    "name": "Arcora Pay",
    "url": "https://arcorapay.xyz",
    "domain": "arcorapay.xyz",
    "alt": "Arcora Pay live website: a light mint interface, lime buttons and a USDC to EURC checkout."
  },
  "celari": {
    "name": "Celari Wallet",
    "url": "https://celariwallet.com",
    "domain": "celariwallet.com",
    "alt": "Celari live website: black and gold branding with the Celari wallet phone interface."
  },
  "swap": {
    "name": "ArcoraDEX",
    "url": "https://swap.arcorapay.xyz",
    "domain": "swap.arcorapay.xyz",
    "alt": "ArcoraDEX live application: a dark green swap interface with lime accents and USDC and USDT selectors."
  },
  "quetzal": {
    "name": "Quetzal DEX",
    "url": "https://quetzaldex.xyz",
    "domain": "quetzaldex.xyz",
    "alt": "Quetzal live website: cream background, expressive serif typography, a dark green clearing panel and lime actions."
  },
  "perp": {
    "name": "Arcora Perp",
    "url": "https://perp.arcoralabs.xyz",
    "domain": "perp.arcoralabs.xyz",
    "alt": "Arcora Perp live landing page: the warm cream and coral interface, Arcora ribbon and trading workspace preview."
  }
};
const image = document.getElementById('selected-image');
const screen = document.querySelector('.selected-screen');
const nameLabel = document.getElementById('selected-name');
const domainLink = document.getElementById('selected-domain');
const previewButtons = [...document.querySelectorAll('[data-preview]')];
previewButtons.forEach(button => button.addEventListener('click', () => {
  const id = button.dataset.preview;
  const project = projects[id];
  previewButtons.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
  image.src = `/assets/projects/${id}.jpg`;
  image.alt = project.alt;
  screen.href = project.url;
  screen.setAttribute('aria-label', `Visit ${project.name}`);
  nameLabel.textContent = project.name;
  domainLink.href = project.url;
  domainLink.firstChild.textContent = project.domain + ' ';
}));
const filters = [...document.querySelectorAll('[data-filter]')];
const cards = [...document.querySelectorAll('[data-category]')];
filters.forEach(button => button.addEventListener('click', () => {
  filters.forEach(filter => filter.setAttribute('aria-pressed', String(filter === button)));
  let count = 0;
  cards.forEach(card => {
    card.hidden = button.dataset.filter !== 'all' && card.dataset.category !== button.dataset.filter;
    if (!card.hidden) count++;
  });
  document.getElementById('filter-status').textContent = `${count} ${count === 1 ? 'project' : 'projects'} shown`;
}));
