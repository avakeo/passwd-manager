// 拡張機能の設定。ここは仮の値（リポジトリには実際の接続先を書かない）。
// ビルド（scripts/build-extension.ts）が、Git の管理外の extension.config.local.json の値で、出力の config.js を書き換える。
export const CONFIG: { apiOrigin: string; discordClientId: string } = {
  apiOrigin: 'https://pw-api.example.com',
  discordClientId: '000000000000000000',
};
