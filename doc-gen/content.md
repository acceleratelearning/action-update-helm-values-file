# What's New

Nothing to see here.

This action is only used in [workflow-container-image-publish](https://github.com/acceleratelearning/workflow-container-image-publish) for now.

# Usage

<!-- start usage -->
```yaml
name: Publish Container Image
on:
  workflow_call:
    inputs:
      registry:
        description: The ECR container image registry url
        required: true
        type: string
      repository-name:
        description: The container image repository name (without version tag)
        required: true
        type: string
      role-to-assume:
        description: The arn for the role to be used by this workflow
        required: true
        type: string
      docker-context:
        description: The directory context for docker build
        required: false
        type: string
        default: "."
      title:
        description: The title to be used for a container image label
        required: false
        type: string
        default: ""
      description:
        description: The description to be used for a container image label
        required: false
        type: string
        default: ""
      authors:
        description: The authors to be used for a container image label
        required: false
        type: string
        default: ""
      documentation-url:
        description: The documentation url to be used for a container image label
        required: false
        type: string
        default: ""
      test-target:
        description: A test-target for testing the dockerfile
        required: false
        type: string
        default: ""
      build-target:
        description: A test-target for testing the dockerfile
        required: false
        type: string
        default: ""
      skip-publish-github-release:
        description: Skip the Publish GitHub Release step
        required: false
        type: boolean
        default: false
      helm-github-repo:
        description: The url for a GitHub repo with a helm chart that needs to be updated with the new image tag
        required: false
        type: string
        default: ""
      helm-branch-name:
        description: The branch of the github repo to update
        required: false
        type: string
        default: main
      helm-values-path:
        description: The path for the helm values file to update
        required: false
        type: string
        default: ""
      helm-values-expression:
        description: Identifies the parameter in the helm values file to update
        required: false
        type: string
        default: ""
      build-args:
        description: Additional build args based to docker build
        required: false
        type: string
        default: ""
    secrets:
      major-minor-version:
        description: The major/minor version of the image that will be used to generate the full tag.  This values is a secret so it can take a value from and organization secret such as `secrets.LONESTAR_ITERATION`
        required: true
      docker-github-app-id:
        description: The GitHub Application Id for the GitHub app that will be used to generate a token that is passed to the docker build
        required: false
      docker-github-app-key:
        description: The PEM file contents for the GitHub app that will be used to generate a token that is passed to the docker build
        required: false
      helm-github-app-id:
        description: The GitHub App id of the GitHub app that will be used to update helm-github-repo
        required: false
      helm-github-app-key:
        description: The PEM file contents for the GitHub app that will be used to update helm-github-repo
        required: false
      secret-build-args:
        description: Additional build args based to docker build that are secret
        required: false
      webhook-url:
        description: A webhook for Google Space Notifications (deprecated)
        required: false
concurrency:
  group: "publish-${{ inputs.repository-name }}"
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    env:
      DOCKER_GITHUB_APP_ID: ${{ secrets.docker-github-app-id }} # Can't use secrets in if condition, so use environment variable
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v1-node16
        with:
          role-to-assume: ${{ inputs.role-to-assume }}
          aws-region: us-east-2

      - name: Get GitHub Application Token
        id: get-github-app-token
        if: env.DOCKER_GITHUB_APP_ID != ''
        uses: acceleratelearning/action-get-application-token@v1
        with:
          github-app-id: ${{ secrets.docker-github-app-id }}
          github-app-key: ${{ secrets.docker-github-app-key }}

      - name: Docker Login
        run: aws ecr get-login-password --region us-east-2 | docker login --username AWS --password-stdin ${{ inputs.registry }}

      - name: Get next image tag
        id: get-next-image-tag
        uses: acceleratelearning/action-get-next-ecr-image-tag@v2
        with:
          registry: ${{ inputs.registry }}
          repository-name: ${{ inputs.repository-name }}
          major-minor-version: "${{ secrets.major-minor-version }}"
          determine-pre-release-tag-from-source-branch: true

      - name: Build Builder Image
        if: inputs.build-target != ''
        uses: acceleratelearning/action-build-container-image@v2
        with:
          image-name: ${{ steps.get-next-image-tag.outputs.next-image-name }}-build
          docker-context: ${{ inputs.docker-context }}
          title: ${{ inputs.title }}
          description: ${{ inputs.description }}
          authors: ${{ inputs.authors }}
          documentation-url: ${{ inputs.documentation-url }}
          target: ${{ inputs.build-target }}
          github-token: ${{ steps.get-github-app-token.outputs.github-app-token }}
          build-args: ${{ inputs.build-args }}
          secret-build-args: ${{ secrets.secret-build-args }}

      - name: Test container image
        if: inputs.test-target != ''
        uses: acceleratelearning/action-build-container-image@v2
        with:
          image-name: container-test
          docker-context: ${{ inputs.docker-context }}
          title: ${{ inputs.title }}
          description: ${{ inputs.description }}
          authors: ${{ inputs.authors }}
          documentation-url: ${{ inputs.documentation-url }}
          test-target: ${{ inputs.test-target }}
          github-token: ${{ steps.get-github-app-token.outputs.github-app-token }}
          build-args: ${{ inputs.build-args }}
          secret-build-args: ${{ secrets.secret-build-args }}

      - name: Get Test Results
        if: inputs.test-target != ''
        run: |
          docker run -it --rm container-test cat /testresults/TestResults.xml > TestResults.xml
          cat TestResults.xml
      - name: Build container image
        uses: acceleratelearning/action-build-container-image@v2
        with:
          image-name: ${{ steps.get-next-image-tag.outputs.next-image-name }}
          docker-context: ${{ inputs.docker-context }}
          title: ${{ inputs.title }}
          description: ${{ inputs.description }}
          authors: ${{ inputs.authors }}
          documentation-url: ${{ inputs.documentation-url }}
          github-token: ${{ steps.get-github-app-token.outputs.github-app-token }}
          build-args: ${{ inputs.build-args }}
          secret-build-args: ${{ secrets.secret-build-args }}

      - name: Publish Container Image to ECR
        shell: pwsh
        run: |
          docker push ${{ steps.get-next-image-tag.outputs.next-image-name }}
          Write-Output "::notice:: Published image ${{ steps.get-next-image-tag.outputs.next-image-name }}"
      - name: Get image scan results
        uses: acceleratelearning/action-get-ecr-image-scan-results@v1
        with:
          registry: ${{ inputs.registry }}
          repository-name: ${{ inputs.repository-name }}
          tag: "${{ steps.get-next-image-tag.outputs.next-tag }}"

      - name: Update Helm Values File
        if: inputs.helm-github-repo != ''
        uses: acceleratelearning/action-update-helm-values-file@v2
        with:
          github-repo: ${{ inputs.helm-github-repo }}
          branch-name: ${{ inputs.helm-branch-name }}
          values-directory: ${{ inputs.helm-values-path }}
          source-branch: ${{ github.ref_name }}
          yaml-path-expression: ${{ inputs.helm-values-expression }}
          value: "${{ steps.get-next-image-tag.outputs.next-tag }}"
          github-app-id: ${{ secrets.helm-github-app-id }}
          github-app-key: ${{ secrets.helm-github-app-key }}
```
<!-- end usage -->