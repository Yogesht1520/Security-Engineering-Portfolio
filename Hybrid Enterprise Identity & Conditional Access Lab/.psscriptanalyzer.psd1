@{
    # PSScriptAnalyzer configuration for Enterprise Identity-as-Code
    Severity = @('Error', 'Warning')
    
    # Exclude terminal formatting rules and global mock scopes for integration tests
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidGlobalVars'
    )
}
