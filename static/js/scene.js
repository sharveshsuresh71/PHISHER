/* PhishGuard — live WebGL scene (three.js, no SVG).
 *
 * A displaced, faceted "threat crystal" with fresnel shading + wireframe,
 * an orbiting particle swarm, scanning beam and shockwave rings, rendered
 * through an Unreal bloom pass. It reacts to the analysis state:
 *   idle → scanning → safe | suspicious | phishing
 */
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';

const STATES = {
  idle:       { a: '#7b4dff', b: '#d9c2ff', disp: 0.05, spike: 0.0,  spin: 0.25, radius: 1.0,  jitter: 0.0,  bloom: 0.6, beam: 0 },
  scanning:   { a: '#4f8cff', b: '#b9f3ff', disp: 0.13, spike: 0.0,  spin: 2.4,  radius: 0.55, jitter: 0.0,  bloom: 0.85,  beam: 1 },
  safe:       { a: '#10c98f', b: '#bfffe8', disp: 0.04, spike: 0.0,  spin: 0.3,  radius: 1.05, jitter: 0.0,  bloom: 0.55,  beam: 0 },
  suspicious: { a: '#ff9a14', b: '#ffe2ac', disp: 0.14, spike: 0.08, spin: 0.6,  radius: 1.1,  jitter: 0.02, bloom: 0.75, beam: 0 },
  phishing:   { a: '#ff2457', b: '#ffb4a0', disp: 0.22, spike: 0.26, spin: 0.9,  radius: 1.2,  jitter: 0.06, bloom: 0.95,  beam: 0 },
};

const NOISE_DISPLACE = /* glsl */ `
  uniform float uTime, uDisp, uSpike;
  vec3 displace(vec3 p) {
    float n = sin(p.x*2.7 + uTime*1.1) * sin(p.y*2.3 - uTime*0.9) * sin(p.z*3.1 + uTime*1.3);
    float s = pow(abs(sin(p.x*6.0 + p.y*4.0 + p.z*5.0 + uTime*2.5)), 8.0);
    return p + normalize(p) * (n*uDisp + s*uSpike);
  }
`;

function crystalMaterial() {
  return new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, side: THREE.DoubleSide, blending: THREE.AdditiveBlending,
    uniforms: {
      uTime: { value: 0 }, uDisp: { value: 0.05 }, uSpike: { value: 0 }, uAlpha: { value: 1 },
      uColA: { value: new THREE.Color() }, uColB: { value: new THREE.Color() },
    },
    vertexShader: /* glsl */ `
      ${NOISE_DISPLACE}
      varying vec3 vView; varying vec3 vPos;
      void main() {
        vec3 p = displace(position);
        vec4 mv = modelViewMatrix * vec4(p, 1.0);
        vView = mv.xyz; vPos = position;
        gl_Position = projectionMatrix * mv;
      }`,
    fragmentShader: /* glsl */ `
      uniform vec3 uColA, uColB; uniform float uTime, uAlpha;
      varying vec3 vView; varying vec3 vPos;
      void main() {
        vec3 n = normalize(cross(dFdx(vView), dFdy(vView)));
        vec3 v = normalize(-vView);
        float fres = pow(1.0 - abs(dot(n, v)), 2.0);
        float facet = 0.5 + 0.5*sin(dot(n, vec3(3.0, 5.0, 2.0))*3.0 + uTime*0.7);
        vec3 col = mix(uColA, uColB, clamp(vPos.y*0.35 + 0.5 + facet*0.25, 0.0, 1.0));
        float a = (0.07 + fres*0.5) * uAlpha;
        gl_FragColor = vec4(col * (0.30 + fres*0.95 + facet*0.30), a);
      }`,
  });
}

function edgeMaterial(shared) {
  return new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: { ...shared, uColor: { value: new THREE.Color() } },
    vertexShader: /* glsl */ `
      ${NOISE_DISPLACE}
      void main() { gl_Position = projectionMatrix * modelViewMatrix * vec4(displace(position), 1.0); }`,
    fragmentShader: /* glsl */ `
      uniform vec3 uColor;
      void main() { gl_FragColor = vec4(uColor, 0.38); }`,
  });
}

function particleMaterial() {
  return new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: {
      uTime: { value: 0 }, uRadius: { value: 1 }, uSize: { value: 26 }, uPixel: { value: 1 }, uJitter: { value: 0 },
      uColA: { value: new THREE.Color() }, uColB: { value: new THREE.Color() },
    },
    vertexShader: /* glsl */ `
      uniform float uTime, uRadius, uSize, uPixel, uJitter;
      attribute float aSeed;
      varying float vSeed;
      float hash(float n) { return fract(sin(n) * 43758.5453); }
      void main() {
        vec3 p = position * uRadius;
        float a = uTime * 0.12 * (0.4 + aSeed);
        mat2 r = mat2(cos(a), -sin(a), sin(a), cos(a));
        p.xz = r * p.xz;
        p.y += sin(uTime*0.6 + aSeed*20.0) * 0.08;
        float st = floor(uTime * 14.0);
        p += (vec3(hash(aSeed*91.0+st), hash(aSeed*37.0+st), hash(aSeed*53.0+st)) - 0.5) * uJitter * 4.0;
        vec4 mv = modelViewMatrix * vec4(p, 1.0);
        gl_PointSize = uSize * uPixel * (0.35 + aSeed) / -mv.z;
        gl_Position = projectionMatrix * mv;
        vSeed = aSeed;
      }`,
    fragmentShader: /* glsl */ `
      uniform vec3 uColA, uColB; varying float vSeed;
      void main() {
        float d = length(gl_PointCoord - 0.5);
        if (d > 0.5) discard;
        float a = smoothstep(0.5, 0.0, d);
        gl_FragColor = vec4(mix(uColA, uColB, vSeed), a * 0.9);
      }`,
  });
}

export function createScene(canvas) {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false, powerPreference: 'high-performance' });
  renderer.setClearColor(0x05030a, 1);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05030a, 0.045);
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
  camera.position.set(0, 0, 7);

  // ---------- crystal ----------
  const crystal = new THREE.Group();
  const geo = new THREE.IcosahedronGeometry(1, 2); // already non-indexed (flat faces)
  const solid = new THREE.Mesh(geo, crystalMaterial());
  const edges = new THREE.LineSegments(
    new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(1, 2)),
    edgeMaterial({
      uTime: solid.material.uniforms.uTime, uDisp: solid.material.uniforms.uDisp, uSpike: solid.material.uniforms.uSpike,
    }),
  );
  const core = new THREE.Mesh(
    new THREE.IcosahedronGeometry(0.2, 1),
    new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending }),
  );
  crystal.add(solid, edges, core);
  crystal.scale.set(0.95, 1.45, 0.95); // elongate into a shard
  const root = new THREE.Group();
  root.add(crystal);
  scene.add(root);

  // ---------- particles ----------
  const N = 2600;
  const pos = new Float32Array(N * 3);
  const seed = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    const disk = Math.random() < 0.55;
    const r = disk ? 1.9 + Math.random() * 2.6 : 1.6 + Math.random() * 3.2;
    const th = Math.random() * Math.PI * 2;
    const ph = disk ? Math.PI / 2 + (Math.random() - 0.5) * 0.35 : Math.acos(2 * Math.random() - 1);
    pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
    pos[i * 3 + 1] = r * Math.cos(ph) * (disk ? 1 : 0.8);
    pos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
    seed[i] = Math.random();
  }
  const pg = new THREE.BufferGeometry();
  pg.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  pg.setAttribute('aSeed', new THREE.BufferAttribute(seed, 1));
  const particles = new THREE.Points(pg, particleMaterial());
  particles.frustumCulled = false;
  root.add(particles);

  // distant stars (static)
  const SN = 700, sp = new Float32Array(SN * 3), ss = new Float32Array(SN);
  for (let i = 0; i < SN; i++) {
    const r = 18 + Math.random() * 22, th = Math.random() * 6.283, ph = Math.acos(2 * Math.random() - 1);
    sp[i * 3] = r * Math.sin(ph) * Math.cos(th); sp[i * 3 + 1] = r * Math.cos(ph); sp[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th) - 6;
    ss[i] = Math.random();
  }
  const sg = new THREE.BufferGeometry();
  sg.setAttribute('position', new THREE.BufferAttribute(sp, 3));
  sg.setAttribute('aSeed', new THREE.BufferAttribute(ss, 1));
  const starMat = particleMaterial();
  starMat.uniforms.uSize.value = 60;
  starMat.uniforms.uColA.value.set('#ffffff');
  starMat.uniforms.uColB.value.set('#9a86ff');
  const stars = new THREE.Points(sg, starMat);
  stars.frustumCulled = false;
  scene.add(stars);

  // ---------- rings ----------
  const ringMat = (op) => new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: op, blending: THREE.AdditiveBlending, depthWrite: false });
  const ring1 = new THREE.Mesh(new THREE.TorusGeometry(2.25, 0.007, 8, 220), ringMat(0.5));
  const ring2 = new THREE.Mesh(new THREE.TorusGeometry(2.85, 0.005, 8, 220), ringMat(0.3));
  ring1.rotation.set(1.25, 0.2, 0); ring2.rotation.set(1.9, -0.4, 0.5);
  const beam = new THREE.Mesh(new THREE.TorusGeometry(1.55, 0.016, 8, 160), ringMat(0));
  beam.rotation.x = Math.PI / 2 - 0.45;
  const shock = new THREE.Mesh(new THREE.TorusGeometry(1, 0.012, 8, 160), ringMat(0));
  shock.rotation.x = Math.PI / 2 - 0.55;
  root.add(ring1, ring2, beam, shock);

  // ---------- post ----------
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(512, 512), 0.6, 0.55, 0.32);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  // ---------- state ----------
  const cur = {
    a: new THREE.Color(STATES.idle.a), b: new THREE.Color(STATES.idle.b),
    disp: 0.05, spike: 0, spin: 0.25, radius: 1, jitter: 0, bloom: 0.6, beam: 0,
  };
  let tgt = { ...STATES.idle, a: new THREE.Color(STATES.idle.a), b: new THREE.Color(STATES.idle.b) };
  let shockT = 1, shake = 0, burst = 0, scrollP = 0, spinAngle = 0;
  let speaking = false, voice = 0, voiceT = 0; // voice: smoothed loudness 0..1
  const pointer = { x: 0, y: 0, sx: 0, sy: 0 };

  function setState(name, score = 0.5) {
    const s = STATES[name] || STATES.idle;
    const k = (name === 'phishing' || name === 'suspicious') ? 0.55 + 0.45 * score : 1;
    tgt = {
      ...s, a: new THREE.Color(s.a), b: new THREE.Color(s.b),
      disp: s.disp * k, spike: s.spike * k, jitter: s.jitter * k,
    };
    if (name === 'phishing') shake = 1;
    if (name === 'safe' || name === 'phishing' || name === 'suspicious') pulse();
  }
  function pulse() { shockT = 0; burst = 1; }
  // voice agent hooks: setSpeaking(true/false) while talking, beat() on every spoken word
  function setSpeaking(on) { speaking = !!on; if (!on) voiceT = 0; }
  function beat(strength = 1) { voiceT = Math.min(1, 0.55 + 0.45 * strength); }
  function setScroll(p) { scrollP = Math.min(Math.max(p, 0), 1); }

  addEventListener('pointermove', (e) => {
    pointer.x = (e.clientX / innerWidth) * 2 - 1;
    pointer.y = (e.clientY / innerHeight) * 2 - 1;
  }, { passive: true });
  canvas.addEventListener('pointerdown', () => pulse());

  function resize() {
    const w = innerWidth, h = innerHeight, dpr = Math.min(devicePixelRatio || 1, 2);
    renderer.setPixelRatio(dpr);
    renderer.setSize(w, h, false);
    composer.setPixelRatio(dpr);
    composer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    const narrow = camera.aspect < 0.85;
    root.userData.base = narrow ? 0.72 : camera.aspect < 1.2 ? 0.9 : 1;
    particles.material.uniforms.uPixel.value = starMat.uniforms.uPixel.value = dpr * Math.max(h, 500) / 900;
  }
  addEventListener('resize', resize);
  resize();

  // ---------- loop ----------
  const clock = new THREE.Clock();
  const matU = solid.material.uniforms, pU = particles.material.uniforms;
  let raf = 0, running = true;

  function frame() {
    raf = requestAnimationFrame(frame);
    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.elapsedTime * (reduced ? 0.3 : 1);
    const k = 1 - Math.exp(-dt * 3.2);

    cur.a.lerp(tgt.a, k); cur.b.lerp(tgt.b, k);
    for (const key of ['disp', 'spike', 'spin', 'radius', 'jitter', 'bloom', 'beam']) cur[key] += (tgt[key] - cur[key]) * k;

    matU.uTime.value = t; matU.uDisp.value = cur.disp + voice * 0.12; matU.uSpike.value = cur.spike;
    matU.uColA.value.copy(cur.a); matU.uColB.value.copy(cur.b);
    edges.material.uniforms.uColor.value.copy(cur.b);
    pU.uTime.value = t; pU.uRadius.value = cur.radius + voice * 0.1; pU.uJitter.value = cur.jitter;
    pU.uColA.value.copy(cur.a); pU.uColB.value.copy(cur.b);
    starMat.uniforms.uTime.value = t * 0.3;

    // motion
    spinAngle += dt * cur.spin * (reduced ? 0.3 : 1);
    pointer.sx += (pointer.x - pointer.sx) * k * 0.6;
    pointer.sy += (pointer.y - pointer.sy) * k * 0.6;
    const base = root.userData.base || 1;
    burst *= Math.exp(-dt * 3);
    // speaking: loudness follows word beats, with a gentle talking shimmer between words
    voiceT *= Math.exp(-dt * 5);
    const vTarget = speaking ? Math.max(voiceT, 0.18 + 0.12 * Math.sin(t * 9) ** 2) : 0;
    voice += (vTarget - voice) * (1 - Math.exp(-dt * 14));
    const sc = base * (1 + burst * 0.12 + voice * 0.07) * (1 - scrollP * 0.32);
    root.scale.setScalar(sc);
    root.rotation.y = pointer.sx * 0.35;
    root.rotation.x = pointer.sy * 0.18;
    crystal.rotation.y = spinAngle;
    crystal.rotation.z = Math.sin(t * 0.5) * 0.06;
    root.position.y = Math.sin(t * 0.8) * 0.12 - scrollP * 0.1;
    shake *= Math.exp(-dt * 2.2);
    root.position.x = Math.sin(t * 70) * 0.03 * shake;
    particles.rotation.y = t * 0.03;
    stars.rotation.y = t * 0.004;
    core.scale.setScalar(0.9 + 0.25 * Math.sin(t * 2.2) + burst * 0.5 + voice * 0.9);
    core.material.color.copy(cur.b);
    camera.position.x = pointer.sx * 0.35;
    camera.position.y = -pointer.sy * 0.2;
    camera.position.z = 7 + scrollP * 1.2;
    camera.lookAt(0, 0, 0);

    ring1.rotation.z += dt * 0.25 * (1 + cur.spin); ring2.rotation.z -= dt * 0.18 * (1 + cur.spin);
    ring1.material.color.copy(cur.b); ring2.material.color.copy(cur.a);
    beam.material.color.copy(cur.b);
    beam.material.opacity = cur.beam * 0.9;
    beam.position.y = Math.sin(t * 3.2) * 1.9;
    beam.scale.setScalar(0.75 + 0.25 * Math.cos(t * 3.2));

    shockT = Math.min(shockT + dt * 0.9, 1);
    const e = 1 - Math.pow(1 - shockT, 3);
    shock.scale.setScalar(1 + e * 5);
    shock.material.opacity = (1 - shockT) * 0.55 * (shockT < 1 ? 1 : 0);
    shock.material.color.copy(cur.b);

    bloom.strength = cur.bloom + burst * 0.35 + voice * 0.5;
    composer.render();
  }
  frame();

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); running = false; }
    else if (!running) { running = true; clock.getDelta(); frame(); }
  });

  return { setState, pulse, setScroll, setSpeaking, beat, renderer };
}
