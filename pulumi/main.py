ecr.LifecyclePolicy(
    config.require(key="ecsName"),
    repository=repo.name,
    policy="""
        {
            "rules":[
                {
                    "rulePriority":1,
                    "description":"Remove old resource",
                    "selection":{
                        "tagStatus":"any",
                        "countType":"imageCountMoreThan",
                        "countNumber": 13
                    },
                    "action":{
                        "type":"expire"
                    }
                }
            ]
        }
    """
)