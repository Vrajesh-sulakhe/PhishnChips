import { useEffect, useRef } from "react";
import * as THREE from "three";
import CubeFallback from "./CubeFallback";

const vertexShader = `
  varying vec3 vNormal;
  varying vec3 vPosition;
  varying vec3 vLocal;
  varying vec2 vUv;
  void main() {
    vLocal = position;
    vUv = uv;
    vec4 world = modelMatrix * vec4(position, 1.0);
    vPosition = world.xyz;
    vNormal = normalize(mat3(modelMatrix) * normal);
    gl_Position = projectionMatrix * viewMatrix * world;
  }
`;

const fragmentShader = `
  uniform float uTime;
  uniform float uScan;
  varying vec3 vNormal;
  varying vec3 vPosition;
  varying vec3 vLocal;
  varying vec2 vUv;

  void main() {
    vec3 n = normalize(vNormal);
    vec3 view = normalize(cameraPosition - vPosition);
    vec2 cells = vUv * 8.0;
    vec2 distanceToLine = abs(fract(cells - .5) - .5);
    vec2 lineWidth = max(fwidth(cells), vec2(.015));
    vec2 lines = 1.0 - smoothstep(lineWidth * .15, lineWidth * .9, distanceToLine);
    float grid = max(lines.x, lines.y);
    float light = max(dot(n, normalize(vec3(-.7, 1.0, 1.8))), 0.0);
    vec3 color = mix(vec3(.009, .002, .0015), vec3(.055, .006, .003), light);
    color += vec3(.11, .023, .010) * grid * (.45 + light * .55 + uScan * .25);
    vec3 reflection = reflect(-view, n);
    float sheen = pow(max(dot(reflection, normalize(vec3(-.6, 1.6, 1.2))), 0.0), 32.0);
    color += vec3(.17, .035, .016) * sheen;
    vec2 faceEdge = abs(vUv - .5) * 2.0;
    float edge = smoothstep(.975, .999, max(faceEdge.x, faceEdge.y));
    color += vec3(.16, .029, .013) * edge;
    float scan = pow(.5 + .5 * sin(vLocal.y * 4.0 - uTime * 2.0), 38.0);
    color += vec3(.2, .025, .009) * scan * uScan;
    gl_FragColor = vec4(color, 1.0);
    #include <tonemapping_fragment>
    #include <colorspace_fragment>
  }
`;

export default function InvestigationCube({ scanning }: { scanning: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const scanningRef = useRef(scanning);
  scanningRef.current = scanning;

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: "low-power",
      });
    } catch {
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    host.appendChild(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 30);
    camera.position.z = 6.4;
    const geometry = new THREE.BoxGeometry(2.2, 2.2, 2.2);
    const material = new THREE.ShaderMaterial({
      vertexShader,
      fragmentShader,
      uniforms: { uTime: { value: 0 }, uScan: { value: 0 } },
    });
    const cube = new THREE.Group();
    cube.add(new THREE.Mesh(geometry, material));
    const edges = new THREE.EdgesGeometry(geometry);
    const edgeMaterial = new THREE.LineBasicMaterial({
      color: 0x9f3a2a,
      transparent: true,
      opacity: 0.62,
    });
    cube.add(new THREE.LineSegments(edges, edgeMaterial));
    // Detached corner brackets make the containment boundary legible.
    const corners: number[] = [];
    for (const x of [-1.23, 1.23]) {
      for (const y of [-1.23, 1.23]) {
        for (const z of [-1.23, 1.23]) {
          corners.push(x, y, z, x - Math.sign(x) * 0.22, y, z);
          corners.push(x, y, z, x, y - Math.sign(y) * 0.22, z);
          corners.push(x, y, z, x, y, z - Math.sign(z) * 0.22);
        }
      }
    }
    const cornerGeometry = new THREE.BufferGeometry();
    cornerGeometry.setAttribute("position", new THREE.Float32BufferAttribute(corners, 3));
    const cornerMaterial = new THREE.LineBasicMaterial({
      color: 0xe26b4b,
      transparent: true,
      opacity: 0.75,
    });
    cube.add(new THREE.LineSegments(cornerGeometry, cornerMaterial));
    cube.rotation.set(0.28, -0.52, 0.06);
    scene.add(cube);
    const pointer = new THREE.Vector2();
    const smoothPointer = new THREE.Vector2();
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    let visible = false;
    let time = 0;
    let last = 0;
    let disposed = false;
    const draw = (now: number) => {
      frame = 0;
      if (disposed || !visible || document.hidden) return;
      const delta = last ? Math.min((now - last) / 1000, 0.05) : 0;
      last = now;
      if (!reducedMotion.matches) time += delta;
      material.uniforms.uTime.value = time;
      material.uniforms.uScan.value +=
        ((scanningRef.current ? 1 : 0) - material.uniforms.uScan.value) * 0.06;
      smoothPointer.lerp(pointer, 0.035);
      cube.rotation.y = -0.52 + time * 0.025 + (reducedMotion.matches ? 0 : smoothPointer.x * 0.12);
      cube.rotation.x =
        0.28 + Math.sin(time * 0.09) * 0.05 + (reducedMotion.matches ? 0 : smoothPointer.y * 0.06);
      renderer.render(scene, camera);
      host.dataset.rendered = "true";
      if (!reducedMotion.matches) frame = requestAnimationFrame(draw);
    };
    const requestDraw = () => {
      if (!frame && !disposed) {
        last = 0;
        frame = requestAnimationFrame(draw);
      }
    };
    const resize = new ResizeObserver(() => {
      const { width, height } = host.getBoundingClientRect();
      if (!width || !height) return;
      renderer.setSize(width, height, false);
      camera.position.z = 6.4;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      requestDraw();
    });
    resize.observe(host);
    const intersection = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible) requestDraw();
      else {
        cancelAnimationFrame(frame);
        frame = 0;
      }
    });
    intersection.observe(host);
    const onPointer = (event: PointerEvent) => {
      pointer.set(
        (event.clientX / window.innerWidth - 0.5) * 2,
        (event.clientY / window.innerHeight - 0.5) * 2,
      );
    };
    const onContextLost = (event: Event) => {
      event.preventDefault();
      host.dataset.rendered = "false";
      cancelAnimationFrame(frame);
    };
    window.addEventListener("pointermove", onPointer, { passive: true });
    document.addEventListener("visibilitychange", requestDraw);
    reducedMotion.addEventListener("change", requestDraw);
    renderer.domElement.addEventListener("webglcontextlost", onContextLost);
    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      resize.disconnect();
      intersection.disconnect();
      window.removeEventListener("pointermove", onPointer);
      document.removeEventListener("visibilitychange", requestDraw);
      reducedMotion.removeEventListener("change", requestDraw);
      geometry.dispose();
      material.dispose();
      edges.dispose();
      edgeMaterial.dispose();
      cornerGeometry.dispose();
      cornerMaterial.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return (
    <div className="cube-scene" ref={hostRef} aria-hidden="true">
      <CubeFallback />
    </div>
  );
}
