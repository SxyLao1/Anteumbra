/* Anteumbra 赛博特效 - Canvas粒子与矩阵雨 */
(function(){
  // 仅在登录页启用矩阵雨
  if (!document.body.classList.contains('login-page')) return;

  // 检查用户是否之前关闭了特效
  const fxDisabled = localStorage.getItem('anteumbra_fx_disabled') === 'true';

  const canvas = document.createElement('canvas');
  canvas.className = 'matrix-bg';
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');

  let W, H, cols, drops = [];
  let fontSize = 14;
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  let animationId = null;
  let isRunning = true;

  // 性能自适应：根据设备调整
  const isLowEnd = navigator.hardwareConcurrency <= 2 || window.innerWidth < 480;
  if (isLowEnd) {
    fontSize = 18; // 更大字体 = 更少列 = 更少计算
  }

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
    cols = Math.floor(W / fontSize);
    drops = Array(cols).fill(1);
  }
  resize();
  window.addEventListener('resize', resize);

  let lastFrame = 0;
  const targetFPS = isLowEnd ? 15 : 30;
  const frameInterval = 1000 / targetFPS;

  function draw(timestamp) {
    if (!isRunning) return;
    animationId = requestAnimationFrame(draw);

    // 帧率限制
    if (timestamp - lastFrame < frameInterval) return;
    lastFrame = timestamp;

    ctx.fillStyle = 'rgba(10, 10, 15, 0.04)';
    ctx.fillRect(0, 0, W, H);
    ctx.font = fontSize + 'px monospace';
    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      const y = drops[i] * fontSize;
      if (y > 0 && y < H) {
        ctx.shadowColor = '#00ff41';
        ctx.shadowBlur = 12;
        const brightness = 0.5 + Math.random() * 0.5;
        ctx.fillStyle = 'rgba(0, 255, 65, ' + brightness + ')';
        ctx.fillText(text, i * fontSize, y);
        if (Math.random() > 0.95) {
          ctx.fillStyle = '#ccffcc';
          ctx.shadowBlur = 16;
          ctx.fillText(text, i * fontSize, y);
        }
      }
      if (y > H && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  // 添加控制按钮
  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'fx-toggle-btn';
  toggleBtn.innerHTML = fxDisabled ? '▶ FX' : '⏸ FX';
  toggleBtn.title = 'Toggle Matrix Rain Effect';
  document.body.appendChild(toggleBtn);

  if (!fxDisabled) {
    animationId = requestAnimationFrame(draw);
  } else {
    // 如果禁用，画一帧静态背景
    ctx.fillStyle = '#0a0a0f';
    ctx.fillRect(0, 0, W, H);
    isRunning = false;
  }

  toggleBtn.addEventListener('click', function() {
    if (isRunning) {
      isRunning = false;
      if (animationId) cancelAnimationFrame(animationId);
      ctx.fillStyle = '#0a0a0f';
      ctx.fillRect(0, 0, W, H);
      toggleBtn.innerHTML = '▶ FX';
      localStorage.setItem('anteumbra_fx_disabled', 'true');
    } else {
      isRunning = true;
      animationId = requestAnimationFrame(draw);
      toggleBtn.innerHTML = '⏸ FX';
      localStorage.setItem('anteumbra_fx_disabled', 'false');
    }
  });
})();

// 仪表盘粒子背景（轻量版）
(function(){
  if (document.body.classList.contains('login-page')) return;
  const canvas = document.createElement('canvas');
  canvas.id = 'particle-canvas';
  canvas.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:0;opacity:0.15;';
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');

  let W, H, particles = [];
  const count = 40;
  let animationId = null;
  let lastFrame = 0;
  const frameInterval = 1000 / 20; // 20fps for particles

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      size: Math.random() * 2 + 1
    });
  }

  function draw(timestamp) {
    animationId = requestAnimationFrame(draw);
    if (timestamp - lastFrame < frameInterval) return;
    lastFrame = timestamp;

    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#00ff41';
    for (let p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();
    }
    // 连线（降低频率）
    ctx.strokeStyle = 'rgba(0,255,65,0.03)';
    ctx.lineWidth = 0.5;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 150) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }
  draw(0);
})();
