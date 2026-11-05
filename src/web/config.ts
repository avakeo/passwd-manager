// Web ページの設定。ここは仮の値（リポジトリには実際の接続先を書かない）。
// ビルド（scripts/build-web.ts）が、Git の管理外の config/web.local.json の値で、出力の config.js を書き換える。
export const CONFIG: { apiOrigin: string; discordClientId: string; webOrigin: string } = {
  apiOrigin: 'https://pw-api.example.com',
  discordClientId: '000000000000000000',
  webOrigin: 'https://pw.example.com',
};
