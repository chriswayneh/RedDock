import ast
import inspect

from app import api


def _called_functions(function: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    return {
        call.func.id
        for call in ast.walk(function)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }


def test_every_dockyard_route_reaches_the_organization_scoped_root_loader():
    tree = ast.parse(inspect.getsource(api))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
    }
    calls = {name: _called_functions(function) for name, function in functions.items()}

    def reaches_root_loader(name: str, visited: frozenset[str] = frozenset()) -> bool:
        if name in visited:
            return False
        direct = calls.get(name, set())
        if "require_dockyard" in direct:
            return True
        return any(
            reaches_root_loader(called, visited | {name})
            for called in direct
            if called in functions
        )

    dockyard_routes: dict[str, str] = {}
    for name, function in functions.items():
        for decorator in function.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            route_path = decorator.args[0]
            if (
                isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "router"
                and isinstance(route_path, ast.Constant)
                and isinstance(route_path.value, str)
                and "{dockyard_id}" in route_path.value
            ):
                dockyard_routes[name] = route_path.value

    assert dockyard_routes
    assert {
        route for name, route in dockyard_routes.items() if not reaches_root_loader(name)
    } == set()
