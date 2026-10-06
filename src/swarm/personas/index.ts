import { AdversarialPersona } from '../types.js';
import { createHackerPersona } from './hackerPersona.js';
import { createConfusedUserPersona } from './confusedUser.js';
import { createLegacySystemPersona } from './legacySystem.js';
import { createConcurrencyRacerPersona } from './concurrencyRacer.js';

export {
  createHackerPersona,
  createConfusedUserPersona,
  createLegacySystemPersona,
  createConcurrencyRacerPersona
};

type PersonaFactory = (id: string) => AdversarialPersona;

interface PersonaMeta {
  type: string;
  focusArea: 'SECURITY' | 'CONCURRENCY' | 'USABILITY' | 'DATA_INTEGRITY';
  factory: PersonaFactory;
  prefix: string;
}

const PERSONA_CATALOG: PersonaMeta[] = [
  {
    type: 'HACKER',
    focusArea: 'SECURITY',
    factory: createHackerPersona,
    prefix: 'hacker'
  },
  {
    type: 'CONCURRENCY_RACER',
    focusArea: 'CONCURRENCY',
    factory: createConcurrencyRacerPersona,
    prefix: 'racer'
  },
  {
    type: 'CONFUSED_USER',
    focusArea: 'USABILITY',
    factory: createConfusedUserPersona,
    prefix: 'confused'
  },
  {
    type: 'LEGACY_SYSTEM',
    focusArea: 'DATA_INTEGRITY',
    factory: createLegacySystemPersona,
    prefix: 'legacy'
  }
];

/**
 * Registry function to generate a virtual persona swarm
 * of requested size and focus areas.
 */
export function generatePersonas(count: number, focusAreas?: string[]): AdversarialPersona[] {
  let eligible = PERSONA_CATALOG;

  if (focusAreas && focusAreas.length > 0) {
    const focusSet = new Set(focusAreas.map(f => f.toUpperCase()));
    const filtered = PERSONA_CATALOG.filter(p => focusSet.has(p.focusArea) || focusSet.has(p.type));
    if (filtered.length > 0) {
      eligible = filtered;
    }
  }

  const personas: AdversarialPersona[] = [];
  for (let i = 0; i < count; i++) {
    const meta = eligible[i % eligible.length];
    const indexNumber = String(Math.floor(i / eligible.length) + 1).padStart(2, '0');
    const id = `${meta.prefix}-${indexNumber}-${i + 1}`;
    personas.push(meta.factory(id));
  }

  return personas;
}
