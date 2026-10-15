@{
    # PSScriptAnalyzer configuration for Enterprise Identity-as-Code
    Severity = @('Error', 'Warning')
    
    # Exclude terminal formatting rules that conflict with CLI console UX
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
