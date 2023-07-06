#!/bin/bash

# usage:
# ./removeDockerImages.sh eu.gcr.io/gematik-all-infra-prod/idp/gsi-server

repository="$1"

function removeDanglingImages()
{
  echo "--- Remove dangling images ---"
  docker_images_output=$(docker images --filter "dangling=true")
  echo
  image_ids=$(echo "$docker_images_output" | awk '{print $3}'| tail -n +2)

  echo dangling "IMAGE IDs:"
  echo "$image_ids"

  for id in $image_ids; do
      echo "Removing dangling image with ID: $id"
      docker rmi "$id"
  done
}

function removeUnusedImagesForRegistry()
{
  echo "--- Remove unused images ---"
  docker_images_output=$(docker images)
  image_ids=$(echo "$docker_images_output" | awk -v repo="$repository" '$1 == repo {print $3}')

  echo "IMAGE IDs for $repository:"
  echo "$image_ids"

  for id in $image_ids; do
      echo "Try removing image with ID: $id"
      docker rmi "$id"
  done
}

removeDanglingImages
echo
removeUnusedImagesForRegistry
exit 0
