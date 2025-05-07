<script>
    import { onMount } from 'svelte';
    import init, { Calculator } from '$lib/pkg/paypy_wasm';

    let result;
    let calculation = 0;
    let greeting = '';

    onMount(async () => {
        await init();
    });

    function calculate() {
        const calc = Calculator.new();
        result = calc.add(calculation);
    }
</script>

<div>
    <h1>{greeting}</h1>
    
    <input type="number" bind:value={calculation}>
    <button on:click={calculate}>Add</button>
    
    {#if result !== 10}
        <p>Result: {result}</p>
    {/if}
</div>
