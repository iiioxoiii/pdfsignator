<?php return array(
    'root' => array(
        'name' => 'pdf-signer/app',
        'pretty_version' => 'dev-main',
        'version' => 'dev-main',
        'reference' => 'f77a867f998ed91a7e5ea762aa47907e89c6cc27',
        'type' => 'project',
        'install_path' => __DIR__ . '/../../',
        'aliases' => array(),
        'dev' => true,
    ),
    'versions' => array(
        'ddn/sapp' => array(
            'pretty_version' => 'dev-main',
            'version' => 'dev-main',
            'reference' => 'e96567de7a9826912223304e613092e2640611c2',
            'type' => 'library',
            'install_path' => __DIR__ . '/../ddn/sapp',
            'aliases' => array(
                0 => '9999999-dev',
            ),
            'dev_requirement' => false,
        ),
        'pdf-signer/app' => array(
            'pretty_version' => 'dev-main',
            'version' => 'dev-main',
            'reference' => 'f77a867f998ed91a7e5ea762aa47907e89c6cc27',
            'type' => 'project',
            'install_path' => __DIR__ . '/../../',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
    ),
);
