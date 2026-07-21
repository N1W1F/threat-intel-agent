// 3D interactive layer (Three.js, vendored locally — see vendor/PROVENANCE.md).
// Two independent scenes:
//   1. An ambient full-viewport particle-network background. Node color and
//      density are driven by REAL decision-agent data (setThreatLevel), not
//      decoration for its own sake — more/redder particles = worse posture.
//   2. A small 3D "health orb" replacing the flat gauge ring, colored and
//      spun by the real health score.
// Both respect prefers-reduced-motion (freeze instead of animate) and pause
// entirely when the tab is hidden. If WebGL is unavailable for any reason,
// everything here no-ops silently and the existing flat CSS/SVG visuals
// (already fully functional on their own) are the fallback — nothing here
// is load-bearing for the app to work.

(function () {
  "use strict";
  if (typeof THREE === "undefined") return; // vendor file missing/blocked — silent fallback

  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let tabHidden = document.hidden;
  document.addEventListener("visibilitychange", () => { tabHidden = document.hidden; });

  function makeGlowTexture(hex) {
    // Procedural radial-gradient sprite — no external image asset needed,
    // keeps this fully offline with zero new files.
    const size = 128;
    const c = document.createElement("canvas");
    c.width = c.height = size;
    const ctx = c.getContext("2d");
    const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    g.addColorStop(0, hex);
    g.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, size, size);
    return new THREE.CanvasTexture(c);
  }

  // ---------------------------------------------------------------------
  // Scene 1: ambient particle network background
  // ---------------------------------------------------------------------
  function initAmbient() {
    const canvas = document.getElementById("scene3dBg");
    if (!canvas) return null;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch {
      return null; // no WebGL context available — fine, CSS background stays visible
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100);
    camera.position.z = 18;

    const COUNT = 90;
    const positions = new Float32Array(COUNT * 3);
    for (let i = 0; i < COUNT; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 30;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 18;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 14;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));

    const sprite = makeGlowTexture("rgba(168,85,247,0.9)");
    const material = new THREE.PointsMaterial({
      size: 0.9, map: sprite, transparent: true, depthWrite: false,
      blending: THREE.AdditiveBlending, color: 0xa855f7,
    });
    const points = new THREE.Points(geo, material);
    scene.add(points);

    // sparse connective lines between near neighbors — computed once, static
    // topology (recomputing every frame would be wasted CPU for a background)
    const lineGeo = new THREE.BufferGeometry();
    const linePos = [];
    for (let i = 0; i < COUNT; i++) {
      for (let j = i + 1; j < COUNT; j++) {
        const dx = positions[i * 3] - positions[j * 3];
        const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
        const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
        const d = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (d < 4.2) {
          linePos.push(positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2]);
          linePos.push(positions[j * 3], positions[j * 3 + 1], positions[j * 3 + 2]);
        }
      }
    }
    lineGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(linePos), 3));
    const lineMat = new THREE.LineBasicMaterial({ color: 0x7c3aed, transparent: true, opacity: 0.12 });
    const lines = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(lines);

    let mouseX = 0, mouseY = 0;
    window.addEventListener("mousemove", (e) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    }, { passive: true });

    function resize() {
      // clientWidth/Height can read 0 (or a stale canvas-default 300x150)
      // if called before the very first layout pass has settled — use
      // getBoundingClientRect() (always current) and re-run once more on
      // the next frame as a belt-and-suspenders guard against that race.
      const r = canvas.getBoundingClientRect();
      const w = r.width || window.innerWidth;
      const h = r.height || window.innerHeight;
      if (w === 0 || h === 0) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);
    resize();
    requestAnimationFrame(resize);

    let raf = null;
    function tick() {
      raf = requestAnimationFrame(tick);
      if (tabHidden) return;
      if (!reduceMotion) {
        points.rotation.y += 0.0006;
        lines.rotation.y = points.rotation.y;
        points.rotation.x += 0.0002;
        lines.rotation.x = points.rotation.x;
        camera.position.x += (mouseX * 1.5 - camera.position.x) * 0.02;
        camera.position.y += (-mouseY * 1.0 - camera.position.y) * 0.02;
        camera.lookAt(0, 0, 0);
      }
      renderer.render(scene, camera);
    }
    tick();

    return {
      setThreatLevel(level) {
        // level: "good" | "warn" | "danger" — recolor the whole network to
        // reflect actual scan posture instead of staying a fixed decoration.
        const colors = { good: 0x3ddc84, warn: 0xf5a524, danger: 0xff4d5e };
        const c = colors[level] || 0xa855f7;
        material.color.setHex(c);
        lineMat.color.setHex(c);
      },
      stop() { if (raf) cancelAnimationFrame(raf); },
    };
  }

  // ---------------------------------------------------------------------
  // Scene 2: 3D health orb
  // ---------------------------------------------------------------------
  function initHealthOrb() {
    const canvas = document.getElementById("healthOrb3d");
    if (!canvas) return null;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch {
      return null;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 20);
    camera.position.z = 4.2;

    const geo = new THREE.IcosahedronGeometry(1.15, 2);
    const material = new THREE.MeshStandardMaterial({
      color: 0x9a90b3, roughness: 0.35, metalness: 0.15,
      emissive: 0x2a1250, emissiveIntensity: 0.4, flatShading: true,
    });
    const orb = new THREE.Mesh(geo, material);
    scene.add(orb);

    const key = new THREE.PointLight(0xffffff, 22, 12);
    key.position.set(3, 2, 4);
    scene.add(key);
    scene.add(new THREE.AmbientLight(0x2a1250, 0.9));

    function resize() {
      const s = canvas.getBoundingClientRect().width || 84;
      if (s === 0) return;
      renderer.setSize(s, s, false);
      camera.aspect = 1;
      camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);
    resize();
    requestAnimationFrame(resize);

    let raf = null;
    function tick() {
      raf = requestAnimationFrame(tick);
      if (tabHidden) return;
      if (!reduceMotion) orb.rotation.y += 0.004;
      renderer.render(scene, camera);
    }
    tick();

    return {
      setScore(score, level) {
        const colors = { good: 0x3ddc84, warn: 0xf5a524, danger: 0xff4d5e };
        const c = score == null ? 0x9a90b3 : (colors[level] || 0x9a90b3);
        material.color.setHex(c);
        material.emissive.setHex(c);
        material.emissiveIntensity = score == null ? 0.15 : 0.35 + (score / 100) * 0.25;
      },
      stop() { if (raf) cancelAnimationFrame(raf); },
    };
  }

  const ambient = initAmbient();
  const orb = initHealthOrb();
  window.scene3d = { ambient, orb };
})();
