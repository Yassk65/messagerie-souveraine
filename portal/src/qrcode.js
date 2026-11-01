/**
 * Générateur de QR Code (ISO/IEC 18004) 100 % autonome en JavaScript pur (Zéro service tiers).
 * Produit une image SVG vectorielle scannable par FreeOTP, Aegis et Google Authenticator.
 *
 * Supporte le mode Byte (8 bits) avec correction d'erreur Reed-Solomon (Niveau L)
 * pour les versions 1 à 10 (jusqu'à 271 octets, idéal pour les URI otpauth://totp/...).
 */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const root = EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecLen) {
  const gen = rsGeneratorPoly(ecLen);
  const msg = new Uint8Array(data.length + ecLen);
  msg.set(data, 0);
  for (let i = 0; i < data.length; i++) {
    const coef = msg[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        msg[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return msg.slice(data.length);
}

// Paramètres Niveau L (Low = 7% d'erreur corrigée) pour Versions 1 à 10 :
// [totalDataCodewords, ecCodewordsPerBlock, numBlocksGroup1, dataCodewordsGroup1, numBlocksGroup2, dataCodewordsGroup2, alignmentCenters]
const VERSION_TABLE_L = [
  null,
  [19, 7, 1, 19, 0, 0, []],
  [34, 10, 1, 34, 0, 0, [6, 18]],
  [55, 15, 1, 55, 0, 0, [6, 22]],
  [80, 20, 1, 80, 0, 0, [6, 26]],
  [108, 26, 1, 108, 0, 0, [6, 30]],
  [136, 18, 2, 68, 0, 0, [6, 34]],
  [156, 20, 2, 78, 0, 0, [6, 22, 38]],
  [194, 24, 2, 97, 0, 0, [6, 24, 42]],
  [232, 30, 2, 116, 0, 0, [6, 26, 46]],
  [274, 18, 2, 68, 2, 69, [6, 28, 50]],
];

function selectVersion(byteLen) {
  for (let v = 1; v <= 10; v++) {
    const capacity = VERSION_TABLE_L[v][0] - (v <= 9 ? 2 : 3);
    if (byteLen <= capacity) return v;
  }
  throw new Error('Texte trop long pour le générateur QR Code');
}

function encodeDataBits(bytes, version) {
  const [totalData] = VERSION_TABLE_L[version];
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };

  // Mode Byte = 0100
  pushBits(0b0100, 4);
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) pushBits(b, 8);

  // Terminaison jusqu'à 4 zéros
  const maxBits = totalData * 8;
  for (let i = 0; i < 4 && bits.length < maxBits; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = new Uint8Array(totalData);
  for (let i = 0; i < bits.length / 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    codewords[i] = byte;
  }

  let padToggle = true;
  for (let i = bits.length / 8; i < totalData; i++) {
    codewords[i] = padToggle ? 0xec : 0x11;
    padToggle = !padToggle;
  }
  return codewords;
}

function interleaveBlocks(codewords, version) {
  const [, ecLen, nb1, dc1, nb2, dc2] = VERSION_TABLE_L[version];
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;

  for (let i = 0; i < nb1; i++) {
    const block = codewords.slice(offset, offset + dc1);
    offset += dc1;
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecLen));
  }
  for (let i = 0; i < nb2; i++) {
    const block = codewords.slice(offset, offset + dc2);
    offset += dc2;
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecLen));
  }

  const result = [];
  const maxDc = Math.max(dc1, dc2);
  for (let i = 0; i < maxDc; i++) {
    for (const db of dataBlocks) {
      if (i < db.length) result.push(db[i]);
    }
  }
  for (let i = 0; i < ecLen; i++) {
    for (const eb of ecBlocks) result.push(eb[i]);
  }
  return result;
}

function buildMatrix(version, finalCodewords) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

  const setFunctionModule = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    modules[r][c] = dark ? 1 : 0;
    isFunc[r][c] = 1;
  };

  const drawFinder = (r, c) => {
    for (let dy = -1; dy <= 7; dy++) {
      for (let dx = -1; dx <= 7; dx++) {
        const xx = c + dx;
        const yy = r + dy;
        if (xx < 0 || xx >= size || yy < 0 || yy >= size) continue;
        const inOuter = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
        const inWhite = dx >= 1 && dx <= 5 && dy >= 1 && dy <= 5;
        const inCenter = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
        setFunctionModule(yy, xx, inOuter && (!inWhite || inCenter));
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setFunctionModule(6, i, i % 2 === 0);
    setFunctionModule(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const align = VERSION_TABLE_L[version][6];
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if (
        (i === 0 && j === 0) ||
        (i === 0 && j === align.length - 1) ||
        (i === align.length - 1 && j === 0)
      ) {
        continue;
      }
      const cr = align[i];
      const cc = align[j];
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          setFunctionModule(cr + dy, cc + dx, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }

  // Dark module & réservations format
  setFunctionModule(size - 8, 8, true);
  for (let i = 0; i < 9; i++) {
    if (!isFunc[8][i]) setFunctionModule(8, i, false);
    if (!isFunc[i][8]) setFunctionModule(i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    if (!isFunc[8][size - 1 - i]) setFunctionModule(8, size - 1 - i, false);
    if (!isFunc[size - 1 - i][8]) setFunctionModule(size - 1 - i, 8, false);
  }

  // Placement des bits de données en zigzag
  const allBits = [];
  for (const b of finalCodewords) {
    for (let i = 7; i >= 0; i--) allBits.push((b >>> i) & 1);
  }

  let bitIdx = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        if (!isFunc[r][c]) {
          const dark = bitIdx < allBits.length ? allBits[bitIdx++] === 1 : false;
          // Masque 0 : (r + c) % 2 === 0
          modules[r][c] = dark ^ ((r + c) % 2 === 0) ? 1 : 0;
        }
      }
    }
    upward = !upward;
  }

  // Bits de format pour Niveau L (01) et Masque 0 (000) -> BCH = 0x77c4
  const formatBits = 0x77c4;
  const getFmtBit = (i) => ((formatBits >>> i) & 1) === 1;

  for (let i = 0; i <= 5; i++) setFunctionModule(8, i, getFmtBit(i));
  setFunctionModule(8, 7, getFmtBit(6));
  setFunctionModule(8, 8, getFmtBit(7));
  setFunctionModule(7, 8, getFmtBit(8));
  for (let i = 9; i < 15; i++) setFunctionModule(14 - i, 8, getFmtBit(i));

  for (let i = 0; i < 8; i++) setFunctionModule(8, size - 1 - i, getFmtBit(i));
  for (let i = 8; i < 15; i++) setFunctionModule(size - 15 + i, 8, getFmtBit(i));

  return modules;
}

function generateQrSvg(text, margin = 3) {
  const bytes = Buffer.from(String(text), 'utf8');
  const version = selectVersion(bytes.length);
  const codewords = encodeDataBits(bytes, version);
  const finalCodewords = interleaveBlocks(codewords, version);
  const matrix = buildMatrix(version, finalCodewords);
  const size = matrix.length;
  const total = size + margin * 2;

  let pathData = '';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        pathData += `M${c + margin},${r + margin}h1v1h-1z`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="180" height="180" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><path d="${pathData}" fill="#0f172a"/></svg>`;
}

module.exports = { generateQrSvg };

