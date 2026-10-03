# デプロイ手順
## Vercel (プロキシ本体)
1. このフォルダをGitHubリポジトリにpush
2. Vercelで Import → そのままDeploy (Framework: Other)
3. https://<project>.vercel.app/ で動作確認

## GitHub Pages (入力フォーム)
1. public/index.html の API_BASE を "https://<project>.vercel.app" に変更
2. そのファイルを別リポジトリ(または gh-pages ブランチ)のルートに置き、Settings → Pages で公開
