/**
 * Gestion des Rôles (RBAC), des Ministères et de la Politique de Classification
 * pour l'administration publique du Burkina Faso.
 *
 * Explication pour le jury :
 * - Chaque agent est rattaché à un Ministère / Institution et possède un rôle :
 *   1. ADMIN_SG     : Administrateur Sécurité / Secrétariat Général (peut enrôler, révoquer, créer des canaux officiels)
 *   2. DIRECTEUR    : Directeur Général / Chef de service (peut émettre des Instructions de Service à valeur probante et messages Confidentiels)
 *   3. AGENT_PUBLIC : Agent assermenté (peut échanger en Normal et Diffusion Restreinte, accuser réception des instructions)
 */

const MINISTRIES = [
  {
    code: 'MTDPCE',
    name: 'Ministère de la Transition Digitale, des Postes et des Communications Électroniques',
    shortName: 'MTDPCE - DGTD',
  },
  {
    code: 'MEFP',
    name: "Ministère de l'Économie, des Finances et de la Prospective",
    shortName: 'MEFP - Finances',
  },
  {
    code: 'MATDS',
    name: "Ministère de l'Administration Territoriale, de la Décentralisation et de la Sécurité",
    shortName: 'MATDS - Sécurité',
  },
  {
    code: 'MS',
    name: 'Ministère de la Santé et de l’Hygiène Publique',
    shortName: 'MS - Santé',
  },
  {
    code: 'PRESIDENCE',
    name: 'Secrétariat Général du Gouvernement et du Conseil des Ministres',
    shortName: 'SGG-CM',
  },
];

const ROLES = {
  ADMIN_SG: {
    id: 'ADMIN_SG',
    label: 'Administrateur Sécurité (DGTD/SG)',
    matrixPowerLevel: 100,
    permissions: [
      'ENROLL_AGENT',
      'REVOKE_AGENT',
      'CREATE_INSTITUTIONAL_CHANNEL',
      'SEND_CONFIDENTIEL',
      'SEND_INSTRUCTION_SERVICE',
      'REMOTE_WIPE_TRIGGER',
      'VIEW_AUDIT_LOGS',
    ],
  },
  DIRECTEUR: {
    id: 'DIRECTEUR',
    label: 'Directeur / Chef de Service',
    matrixPowerLevel: 50,
    permissions: [
      'CREATE_INSTITUTIONAL_CHANNEL',
      'SEND_CONFIDENTIEL',
      'SEND_INSTRUCTION_SERVICE',
    ],
  },
  AGENT_PUBLIC: {
    id: 'AGENT_PUBLIC',
    label: 'Agent Public Assermenté',
    matrixPowerLevel: 0,
    permissions: ['SEND_NORMAL', 'SEND_DIFFUSION_RESTREINTE', 'ACKNOWLEDGE_INSTRUCTION'],
  },
};

/**
 * Niveaux de classification des messages administratifs et règles associées.
 */
const CLASSIFICATIONS = {
  NORMAL: {
    level: 'NORMAL',
    label: 'Service Standard',
    allowForward: true,
    allowCopy: true,
    BlockScreenshotHint: false,
    ttlSeconds: null, // Pas d'expiration forcée
    minRole: 'AGENT_PUBLIC',
  },
  DIFFUSION_RESTREINTE: {
    level: 'DIFFUSION_RESTREINTE',
    label: 'Diffusion Restreinte',
    allowForward: false,
    allowCopy: false,
    BlockScreenshotHint: true,
    ttlSeconds: 3600, // Expiration automatique 1h (ou personnalisée)
    minRole: 'AGENT_PUBLIC',
  },
  CONFIDENTIEL: {
    level: 'CONFIDENTIEL',
    label: 'Confidentiel État',
    allowForward: false,
    allowCopy: false,
    BlockScreenshotHint: true,
    ttlSeconds: 300, // Expiration automatique 5 min par défaut
    minRole: 'DIRECTEUR', // Réservé aux Directeurs et Administrateurs SG
  },
};

function hasPermission(roleId, permission) {
  const role = ROLES[roleId];
  if (!role) return false;
  return role.permissions.includes(permission);
}

function canUseClassification(roleId, classificationLevel) {
  const spec = CLASSIFICATIONS[classificationLevel];
  if (!spec) return false;
  if (classificationLevel === 'CONFIDENTIEL') {
    return roleId === 'ADMIN_SG' || roleId === 'DIRECTEUR';
  }
  return Boolean(ROLES[roleId]);
}

/**
 * Comptes de démonstration fictifs pré-enrôlés (conformes aux règles du hackathon).
 */
const DEFAULT_DEMO_AGENTS = [
  {
    localpart: 'admin',
    fullName: 'Commandant Ousmane Traoré (Admin DGTD)',
    email: 'ousmane.traore@mtdpce.gov.bf',
    matricule: 'BF-DGTD-0001',
    ministry: 'MTDPCE',
    direction: 'Direction Générale de la Transformation Digitale (DGTD)',
    title: 'Administrateur Sécurité Messagerie',
    role: 'ADMIN_SG',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    status: 'ACTIVE',
  },
  {
    localpart: 'aminata.ouedraogo',
    fullName: 'Aminata Ouédraogo',
    email: 'aminata.ouedraogo@mtdpce.gov.bf',
    matricule: 'BF-MTDPCE-2041',
    ministry: 'MTDPCE',
    direction: 'Direction des Systèmes d’Information',
    title: 'Directrice des Infrastructures Numériques',
    role: 'DIRECTEUR',
    totpSecret: 'JBSWY3DPEHPK3PXQ',
    status: 'ACTIVE',
  },
  {
    localpart: 'ibrahim.sawadogo',
    fullName: 'Ibrahim Sawadogo',
    email: 'ibrahim.sawadogo@mefp.gov.bf',
    matricule: 'BF-MEFP-3108',
    ministry: 'MEFP',
    direction: 'Direction Générale du Trésor et de la Comptabilité Publique',
    title: 'Inspecteur du Trésor',
    role: 'AGENT_PUBLIC',
    totpSecret: 'JBSWY3DPEHPK3PXR',
    status: 'ACTIVE',
  },
  {
    localpart: 'fatoumata.kabore',
    fullName: 'Fatoumata Kaboré',
    email: 'fatoumata.kabore@matds.gov.bf',
    matricule: 'BF-MATDS-1192',
    ministry: 'MATDS',
    direction: 'Direction de la Sécurité des Systèmes et Télécommunications',
    title: 'Chargée des Opérations Territoriales',
    role: 'AGENT_PUBLIC',
    totpSecret: 'JBSWY3DPEHPK3PXS',
    status: 'ACTIVE',
  },
];

module.exports = {
  MINISTRIES,
  ROLES,
  CLASSIFICATIONS,
  DEFAULT_DEMO_AGENTS,
  hasPermission,
  canUseClassification,
};

