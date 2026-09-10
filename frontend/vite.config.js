import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5180,
    allowedHosts: true, // ngrok 등 외부 터널 도메인으로 접속 시 Vite의 Host 헤더 차단을 피하기 위함 (시연용 임시 설정)
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        ws: true,
      }
    }
  }
})
